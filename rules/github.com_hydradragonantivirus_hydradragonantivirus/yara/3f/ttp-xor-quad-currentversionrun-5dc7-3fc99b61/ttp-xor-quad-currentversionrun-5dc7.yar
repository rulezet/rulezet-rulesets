rule TTP_XOR_QUAD_CurrentVersionRun_5dc7 {
  strings:
    $key_5dc7 = { 0e a8 [2] 2a a6 [2] 01 8a [2] 2f a8 [2] 3b b3 [2] 34 a9 [2] 2a b4 [2] 28 b5 [2] 33 b3 [2] 2f b4 [2] 33 9b }

  condition:
    any of them
}