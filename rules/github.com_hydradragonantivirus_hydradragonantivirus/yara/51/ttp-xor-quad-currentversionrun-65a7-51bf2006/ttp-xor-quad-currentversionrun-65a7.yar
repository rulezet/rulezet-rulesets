rule TTP_XOR_QUAD_CurrentVersionRun_65a7 {
  strings:
    $key_65a7 = { 36 c8 [2] 12 c6 [2] 39 ea [2] 17 c8 [2] 03 d3 [2] 0c c9 [2] 12 d4 [2] 10 d5 [2] 0b d3 [2] 17 d4 [2] 0b fb }

  condition:
    any of them
}