package htpasswd

import (
	"crypto/sha1"
	"encoding/base64"
	"os/exec"

	"golang.org/x/crypto/bcrypt"
)

func hashSha(password string) string {
	s := sha1.New()
	s.Write([]byte(password))
	passwordSum := []byte(s.Sum(nil))
	return base64.StdEncoding.EncodeToString(passwordSum)
}

func hashBcrypt(password string) (hash string, err error) {
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	return string(passwordBytes), nil
}
//参照python版的md5
func md5(password string) string {
	command := "openssl passwd -apr1 " + password
	newpass, _ := exec.Command("/bin/bash", "-c", command).Output()
	return string(newpass)
}
