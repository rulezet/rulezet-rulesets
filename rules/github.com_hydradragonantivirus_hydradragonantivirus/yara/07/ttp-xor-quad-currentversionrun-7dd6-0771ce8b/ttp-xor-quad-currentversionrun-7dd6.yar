rule TTP_XOR_QUAD_CurrentVersionRun_7dd6 {
  strings:
    $key_7dd6 = { 2e b9 [2] 0a b7 [2] 21 9b [2] 0f b9 [2] 1b a2 [2] 14 b8 [2] 0a a5 [2] 08 a4 [2] 13 a2 [2] 0f a5 [2] 13 8a }

  condition:
    any of them
}