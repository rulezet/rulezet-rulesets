rule TTP_XOR_QUAD_CurrentVersionRun_52a7 {
  strings:
    $key_52a7 = { 01 c8 [2] 25 c6 [2] 0e ea [2] 20 c8 [2] 34 d3 [2] 3b c9 [2] 25 d4 [2] 27 d5 [2] 3c d3 [2] 20 d4 [2] 3c fb }

  condition:
    any of them
}