rule TTP_XOR_QUAD_CurrentVersionRun_58d6 {
  strings:
    $key_58d6 = { 0b b9 [2] 2f b7 [2] 04 9b [2] 2a b9 [2] 3e a2 [2] 31 b8 [2] 2f a5 [2] 2d a4 [2] 36 a2 [2] 2a a5 [2] 36 8a }

  condition:
    any of them
}