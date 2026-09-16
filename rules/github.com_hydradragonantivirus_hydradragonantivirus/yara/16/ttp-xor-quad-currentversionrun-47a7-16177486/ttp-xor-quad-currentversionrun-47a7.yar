rule TTP_XOR_QUAD_CurrentVersionRun_47a7 {
  strings:
    $key_47a7 = { 14 c8 [2] 30 c6 [2] 1b ea [2] 35 c8 [2] 21 d3 [2] 2e c9 [2] 30 d4 [2] 32 d5 [2] 29 d3 [2] 35 d4 [2] 29 fb }

  condition:
    any of them
}