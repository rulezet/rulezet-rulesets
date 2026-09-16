rule TTP_XOR_QUAD_CurrentVersionRun_66a7 {
  strings:
    $key_66a7 = { 35 c8 [2] 11 c6 [2] 3a ea [2] 14 c8 [2] 00 d3 [2] 0f c9 [2] 11 d4 [2] 13 d5 [2] 08 d3 [2] 14 d4 [2] 08 fb }

  condition:
    any of them
}