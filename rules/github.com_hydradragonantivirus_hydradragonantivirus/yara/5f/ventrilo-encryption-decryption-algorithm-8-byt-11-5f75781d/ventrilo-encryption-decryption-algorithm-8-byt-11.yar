rule Ventrilo_encryption_decryption_algorithm__8_byt_11_ {
  strings:
    $a0 = { aa 55 22 cc 69 7c 38 91 88 f5 e1 }

  condition:
    $a0
}