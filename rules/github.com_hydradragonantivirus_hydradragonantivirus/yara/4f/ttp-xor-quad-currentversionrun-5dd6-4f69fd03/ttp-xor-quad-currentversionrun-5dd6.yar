rule TTP_XOR_QUAD_CurrentVersionRun_5dd6 {
  strings:
    $key_5dd6 = { 0e b9 [2] 2a b7 [2] 01 9b [2] 2f b9 [2] 3b a2 [2] 34 b8 [2] 2a a5 [2] 28 a4 [2] 33 a2 [2] 2f a5 [2] 33 8a }

  condition:
    any of them
}