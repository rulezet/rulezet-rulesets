rule TTP_XOR_QUAD_CurrentVersionRun_20a7 {
  strings:
    $key_20a7 = { 73 c8 [2] 57 c6 [2] 7c ea [2] 52 c8 [2] 46 d3 [2] 49 c9 [2] 57 d4 [2] 55 d5 [2] 4e d3 [2] 52 d4 [2] 4e fb }

  condition:
    any of them
}