rule Stealer {
  strings:
    $a = "dump-generic-passwords"
    $b = "keychain-db"
    $A = "dump-generic-passwords" base64
    $B = "keychain-db" base64

  condition:
    any of them
}