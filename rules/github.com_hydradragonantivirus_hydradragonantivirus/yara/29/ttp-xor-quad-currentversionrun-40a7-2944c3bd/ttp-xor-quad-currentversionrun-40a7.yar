rule TTP_XOR_QUAD_CurrentVersionRun_40a7 {
  strings:
    $key_40a7 = { 13 c8 [2] 37 c6 [2] 1c ea [2] 32 c8 [2] 26 d3 [2] 29 c9 [2] 37 d4 [2] 35 d5 [2] 2e d3 [2] 32 d4 [2] 2e fb }

  condition:
    any of them
}