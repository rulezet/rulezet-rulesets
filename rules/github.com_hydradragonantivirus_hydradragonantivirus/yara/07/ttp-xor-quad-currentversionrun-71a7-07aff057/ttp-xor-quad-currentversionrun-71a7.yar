rule TTP_XOR_QUAD_CurrentVersionRun_71a7 {
  strings:
    $key_71a7 = { 22 c8 [2] 06 c6 [2] 2d ea [2] 03 c8 [2] 17 d3 [2] 18 c9 [2] 06 d4 [2] 04 d5 [2] 1f d3 [2] 03 d4 [2] 1f fb }

  condition:
    any of them
}