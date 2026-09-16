rule Tiger_crypto_algorithm_init__64_big_AND_ {
  strings:
    $a0 = { 01 23 45 67 89 ab cd ef [0-20] fe dc ba 98 76 54 32 10 [0-20] f0 96 a5 b4 c3 b2 e1 87 }

  condition:
    $a0
}