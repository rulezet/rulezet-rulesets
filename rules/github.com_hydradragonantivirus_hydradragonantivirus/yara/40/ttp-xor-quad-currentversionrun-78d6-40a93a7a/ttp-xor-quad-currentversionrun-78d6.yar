rule TTP_XOR_QUAD_CurrentVersionRun_78d6 {
  strings:
    $key_78d6 = { 2b b9 [2] 0f b7 [2] 24 9b [2] 0a b9 [2] 1e a2 [2] 11 b8 [2] 0f a5 [2] 0d a4 [2] 16 a2 [2] 0a a5 [2] 16 8a }

  condition:
    any of them
}