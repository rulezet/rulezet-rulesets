rule TTP_XOR_QUAD_CurrentVersionRun_74a7 {
  strings:
    $key_74a7 = { 27 c8 [2] 03 c6 [2] 28 ea [2] 06 c8 [2] 12 d3 [2] 1d c9 [2] 03 d4 [2] 01 d5 [2] 1a d3 [2] 06 d4 [2] 1a fb }

  condition:
    any of them
}