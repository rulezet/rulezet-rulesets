rule TTP_XOR_QUAD_CurrentVersionRun_54a7 {
  strings:
    $key_54a7 = { 07 c8 [2] 23 c6 [2] 08 ea [2] 26 c8 [2] 32 d3 [2] 3d c9 [2] 23 d4 [2] 21 d5 [2] 3a d3 [2] 26 d4 [2] 3a fb }

  condition:
    any of them
}