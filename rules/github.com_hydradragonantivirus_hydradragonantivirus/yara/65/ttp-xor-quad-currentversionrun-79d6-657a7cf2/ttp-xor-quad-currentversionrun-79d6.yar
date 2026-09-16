rule TTP_XOR_QUAD_CurrentVersionRun_79d6 {
  strings:
    $key_79d6 = { 2a b9 [2] 0e b7 [2] 25 9b [2] 0b b9 [2] 1f a2 [2] 10 b8 [2] 0e a5 [2] 0c a4 [2] 17 a2 [2] 0b a5 [2] 17 8a }

  condition:
    any of them
}