rule TTP_XOR_QUAD_CurrentVersionRun_96a7 {
  strings:
    $key_96a7 = { c5 c8 [2] e1 c6 [2] ca ea [2] e4 c8 [2] f0 d3 [2] ff c9 [2] e1 d4 [2] e3 d5 [2] f8 d3 [2] e4 d4 [2] f8 fb }

  condition:
    any of them
}