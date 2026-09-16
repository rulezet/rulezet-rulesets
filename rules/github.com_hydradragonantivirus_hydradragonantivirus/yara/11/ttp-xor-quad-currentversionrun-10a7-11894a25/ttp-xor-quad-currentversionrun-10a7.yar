rule TTP_XOR_QUAD_CurrentVersionRun_10a7 {
  strings:
    $key_10a7 = { 43 c8 [2] 67 c6 [2] 4c ea [2] 62 c8 [2] 76 d3 [2] 79 c9 [2] 67 d4 [2] 65 d5 [2] 7e d3 [2] 62 d4 [2] 7e fb }

  condition:
    any of them
}