rule TTP_XOR_QUAD_CurrentVersionRun_7dc7 {
  strings:
    $key_7dc7 = { 2e a8 [2] 0a a6 [2] 21 8a [2] 0f a8 [2] 1b b3 [2] 14 a9 [2] 0a b4 [2] 08 b5 [2] 13 b3 [2] 0f b4 [2] 13 9b }

  condition:
    any of them
}