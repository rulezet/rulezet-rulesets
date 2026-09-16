rule TTP_XOR_QUAD_CurrentVersionRun_6dd6 {
  strings:
    $key_6dd6 = { 3e b9 [2] 1a b7 [2] 31 9b [2] 1f b9 [2] 0b a2 [2] 04 b8 [2] 1a a5 [2] 18 a4 [2] 03 a2 [2] 1f a5 [2] 03 8a }

  condition:
    any of them
}