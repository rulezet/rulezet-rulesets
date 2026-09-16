rule Speed_Challenge_network_encryption_decryption_algorithm_X4d4638__8_byt_37_ {
  strings:
    $a0 = { f7 a9 66 11 e1 10 ec c6 7b 67 6a d4 4b 67 38 da 98 38 ec 3a 95 82 dd 5a ea 86 28 53 d8 02 1e 67 24 4f b9 f7 6e }

  condition:
    $a0
}