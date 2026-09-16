rule TTP_XOR_QUAD_CurrentVersionRun_7dc6 {
  strings:
    $key_7dc6 = { 2e a9 [2] 0a a7 [2] 21 8b [2] 0f a9 [2] 1b b2 [2] 14 a8 [2] 0a b5 [2] 08 b4 [2] 13 b2 [2] 0f b5 [2] 13 9a }

  condition:
    any of them
}