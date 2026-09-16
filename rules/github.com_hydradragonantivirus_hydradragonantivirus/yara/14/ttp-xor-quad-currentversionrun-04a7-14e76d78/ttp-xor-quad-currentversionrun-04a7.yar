rule TTP_XOR_QUAD_CurrentVersionRun_04a7 {
  strings:
    $key_04a7 = { 57 c8 [2] 73 c6 [2] 58 ea [2] 76 c8 [2] 62 d3 [2] 6d c9 [2] 73 d4 [2] 71 d5 [2] 6a d3 [2] 76 d4 [2] 6a fb }

  condition:
    any of them
}