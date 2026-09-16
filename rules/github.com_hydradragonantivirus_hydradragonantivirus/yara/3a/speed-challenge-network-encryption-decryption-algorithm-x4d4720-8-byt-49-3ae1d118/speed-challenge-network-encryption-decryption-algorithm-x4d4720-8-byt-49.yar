rule Speed_Challenge_network_encryption_decryption_algorithm_X4d4720__8_byt_49_ {
  strings:
    $a0 = { 52 7a 88 4b 39 64 b2 54 61 19 24 5f 9b be 6b 6e c6 b8 10 a7 d7 aa 22 bc d3 ea f9 3e 52 5d c9 17 11 cf 20 56 4c e6 53 d4 0b d7 b2 76 63 1e f3 86 91 }

  condition:
    $a0
}