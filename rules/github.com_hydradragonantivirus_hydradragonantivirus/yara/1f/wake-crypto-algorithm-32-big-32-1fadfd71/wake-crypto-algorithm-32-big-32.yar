rule Wake_crypto_algorithm__32_big_32_ {
  strings:
    $a0 = { 72 6a 8f 3b e6 9a 3b 5c d3 c7 1f e5 ab 3c 73 d2 4d 3a 8e b3 03 96 d6 e8 3d 4c 2f 7a 9e e2 7c f3 }

  condition:
    $a0
}