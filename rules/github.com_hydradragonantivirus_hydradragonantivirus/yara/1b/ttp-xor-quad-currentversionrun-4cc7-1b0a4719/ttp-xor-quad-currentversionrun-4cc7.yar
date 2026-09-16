rule TTP_XOR_QUAD_CurrentVersionRun_4cc7 {
  strings:
    $key_4cc7 = { 1f a8 [2] 3b a6 [2] 10 8a [2] 3e a8 [2] 2a b3 [2] 25 a9 [2] 3b b4 [2] 39 b5 [2] 22 b3 [2] 3e b4 [2] 22 9b }

  condition:
    any of them
}