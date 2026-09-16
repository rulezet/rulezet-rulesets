rule TTP_XOR_QUAD_CurrentVersionRun_49d7 {
  strings:
    $key_49d7 = { 1a b8 [2] 3e b6 [2] 15 9a [2] 3b b8 [2] 2f a3 [2] 20 b9 [2] 3e a4 [2] 3c a5 [2] 27 a3 [2] 3b a4 [2] 27 8b }

  condition:
    any of them
}