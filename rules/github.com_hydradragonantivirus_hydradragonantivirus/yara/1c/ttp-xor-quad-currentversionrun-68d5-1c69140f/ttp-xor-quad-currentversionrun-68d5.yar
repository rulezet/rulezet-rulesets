rule TTP_XOR_QUAD_CurrentVersionRun_68d5 {
  strings:
    $key_68d5 = { 3b ba [2] 1f b4 [2] 34 98 [2] 1a ba [2] 0e a1 [2] 01 bb [2] 1f a6 [2] 1d a7 [2] 06 a1 [2] 1a a6 [2] 06 89 }

  condition:
    any of them
}