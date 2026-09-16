rule TTP_XOR_QUAD_CurrentVersionRun_a1a7 {
  strings:
    $key_a1a7 = { f2 c8 [2] d6 c6 [2] fd ea [2] d3 c8 [2] c7 d3 [2] c8 c9 [2] d6 d4 [2] d4 d5 [2] cf d3 [2] d3 d4 [2] cf fb }

  condition:
    any of them
}