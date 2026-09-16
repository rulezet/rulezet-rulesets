rule TTP_XOR_QUAD_CurrentVersionRun_b4a7 {
  strings:
    $key_b4a7 = { e7 c8 [2] c3 c6 [2] e8 ea [2] c6 c8 [2] d2 d3 [2] dd c9 [2] c3 d4 [2] c1 d5 [2] da d3 [2] c6 d4 [2] da fb }

  condition:
    any of them
}