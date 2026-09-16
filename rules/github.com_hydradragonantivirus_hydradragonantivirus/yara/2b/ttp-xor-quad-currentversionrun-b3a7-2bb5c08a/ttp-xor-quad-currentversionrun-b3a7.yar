rule TTP_XOR_QUAD_CurrentVersionRun_b3a7 {
  strings:
    $key_b3a7 = { e0 c8 [2] c4 c6 [2] ef ea [2] c1 c8 [2] d5 d3 [2] da c9 [2] c4 d4 [2] c6 d5 [2] dd d3 [2] c1 d4 [2] dd fb }

  condition:
    any of them
}