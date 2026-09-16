rule TTP_XOR_QUAD_CurrentVersionRun_77a7 {
  strings:
    $key_77a7 = { 24 c8 [2] 00 c6 [2] 2b ea [2] 05 c8 [2] 11 d3 [2] 1e c9 [2] 00 d4 [2] 02 d5 [2] 19 d3 [2] 05 d4 [2] 19 fb }

  condition:
    any of them
}