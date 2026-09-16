rule TTP_XOR_QUAD_CurrentVersionRun_1cc7 {
  strings:
    $key_1cc7 = { 4f a8 [2] 6b a6 [2] 40 8a [2] 6e a8 [2] 7a b3 [2] 75 a9 [2] 6b b4 [2] 69 b5 [2] 72 b3 [2] 6e b4 [2] 72 9b }

  condition:
    any of them
}