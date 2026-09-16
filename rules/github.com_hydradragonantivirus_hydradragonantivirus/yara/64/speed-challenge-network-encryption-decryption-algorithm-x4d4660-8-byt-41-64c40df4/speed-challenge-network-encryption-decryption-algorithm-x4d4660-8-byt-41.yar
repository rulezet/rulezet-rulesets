rule Speed_Challenge_network_encryption_decryption_algorithm_X4d4660__8_byt_41_ {
  strings:
    $a0 = { 9b 48 e9 d2 e4 f9 86 60 b0 95 13 67 9d 3e 70 8e d2 77 c3 f8 2e 2a 8d 61 57 69 f3 b9 c8 4f 30 a0 52 c9 84 16 2d ce c3 2f 99 }

  condition:
    $a0
}