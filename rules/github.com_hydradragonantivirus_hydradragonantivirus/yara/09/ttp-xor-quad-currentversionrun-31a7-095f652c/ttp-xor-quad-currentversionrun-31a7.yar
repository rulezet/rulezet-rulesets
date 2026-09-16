rule TTP_XOR_QUAD_CurrentVersionRun_31a7 {
  strings:
    $key_31a7 = { 62 c8 [2] 46 c6 [2] 6d ea [2] 43 c8 [2] 57 d3 [2] 58 c9 [2] 46 d4 [2] 44 d5 [2] 5f d3 [2] 43 d4 [2] 5f fb }

  condition:
    any of them
}