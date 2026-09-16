rule TTP_XOR_QUAD_CurrentVersionRun_1dd6 {
  strings:
    $key_1dd6 = { 4e b9 [2] 6a b7 [2] 41 9b [2] 6f b9 [2] 7b a2 [2] 74 b8 [2] 6a a5 [2] 68 a4 [2] 73 a2 [2] 6f a5 [2] 73 8a }

  condition:
    any of them
}