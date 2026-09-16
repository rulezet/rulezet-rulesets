rule TTP_XOR_QUAD_CurrentVersionRun_42a7 {
  strings:
    $key_42a7 = { 11 c8 [2] 35 c6 [2] 1e ea [2] 30 c8 [2] 24 d3 [2] 2b c9 [2] 35 d4 [2] 37 d5 [2] 2c d3 [2] 30 d4 [2] 2c fb }

  condition:
    any of them
}