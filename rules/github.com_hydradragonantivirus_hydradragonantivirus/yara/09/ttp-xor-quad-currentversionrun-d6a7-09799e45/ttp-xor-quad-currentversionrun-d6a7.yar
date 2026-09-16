rule TTP_XOR_QUAD_CurrentVersionRun_d6a7 {
  strings:
    $key_d6a7 = { 85 c8 [2] a1 c6 [2] 8a ea [2] a4 c8 [2] b0 d3 [2] bf c9 [2] a1 d4 [2] a3 d5 [2] b8 d3 [2] a4 d4 [2] b8 fb }

  condition:
    any of them
}