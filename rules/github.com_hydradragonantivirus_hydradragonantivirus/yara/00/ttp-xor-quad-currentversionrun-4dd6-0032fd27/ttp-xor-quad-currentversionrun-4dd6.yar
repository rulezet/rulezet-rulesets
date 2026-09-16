rule TTP_XOR_QUAD_CurrentVersionRun_4dd6 {
  strings:
    $key_4dd6 = { 1e b9 [2] 3a b7 [2] 11 9b [2] 3f b9 [2] 2b a2 [2] 24 b8 [2] 3a a5 [2] 38 a4 [2] 23 a2 [2] 3f a5 [2] 23 8a }

  condition:
    any of them
}