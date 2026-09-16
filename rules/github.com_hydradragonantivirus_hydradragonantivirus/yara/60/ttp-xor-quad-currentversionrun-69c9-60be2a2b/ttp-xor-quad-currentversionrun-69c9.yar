rule TTP_XOR_QUAD_CurrentVersionRun_69c9 {
  strings:
    $key_69c9 = { 3a a6 [2] 1e a8 [2] 35 84 [2] 1b a6 [2] 0f bd [2] 00 a7 [2] 1e ba [2] 1c bb [2] 07 bd [2] 1b ba [2] 07 95 }

  condition:
    any of them
}