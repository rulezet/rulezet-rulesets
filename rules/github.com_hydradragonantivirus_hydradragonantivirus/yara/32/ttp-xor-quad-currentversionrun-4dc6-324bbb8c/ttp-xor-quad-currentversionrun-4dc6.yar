rule TTP_XOR_QUAD_CurrentVersionRun_4dc6 {
  strings:
    $key_4dc6 = { 1e a9 [2] 3a a7 [2] 11 8b [2] 3f a9 [2] 2b b2 [2] 24 a8 [2] 3a b5 [2] 38 b4 [2] 23 b2 [2] 3f b5 [2] 23 9a }

  condition:
    any of them
}