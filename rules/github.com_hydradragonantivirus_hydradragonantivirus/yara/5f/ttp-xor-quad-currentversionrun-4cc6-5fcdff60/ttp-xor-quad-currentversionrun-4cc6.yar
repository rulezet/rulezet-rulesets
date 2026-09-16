rule TTP_XOR_QUAD_CurrentVersionRun_4cc6 {
  strings:
    $key_4cc6 = { 1f a9 [2] 3b a7 [2] 10 8b [2] 3e a9 [2] 2a b2 [2] 25 a8 [2] 3b b5 [2] 39 b4 [2] 22 b2 [2] 3e b5 [2] 22 9a }

  condition:
    any of them
}