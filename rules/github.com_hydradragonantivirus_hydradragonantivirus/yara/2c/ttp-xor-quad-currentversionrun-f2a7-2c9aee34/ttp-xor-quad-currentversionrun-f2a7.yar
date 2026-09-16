rule TTP_XOR_QUAD_CurrentVersionRun_f2a7 {
  strings:
    $key_f2a7 = { a1 c8 [2] 85 c6 [2] ae ea [2] 80 c8 [2] 94 d3 [2] 9b c9 [2] 85 d4 [2] 87 d5 [2] 9c d3 [2] 80 d4 [2] 9c fb }

  condition:
    any of them
}