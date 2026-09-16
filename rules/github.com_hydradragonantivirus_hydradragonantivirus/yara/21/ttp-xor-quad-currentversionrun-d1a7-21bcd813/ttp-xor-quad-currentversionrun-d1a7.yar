rule TTP_XOR_QUAD_CurrentVersionRun_d1a7 {
  strings:
    $key_d1a7 = { 82 c8 [2] a6 c6 [2] 8d ea [2] a3 c8 [2] b7 d3 [2] b8 c9 [2] a6 d4 [2] a4 d5 [2] bf d3 [2] a3 d4 [2] bf fb }

  condition:
    any of them
}