rule TTP_XOR_QUAD_CurrentVersionRun_a6a7 {
  strings:
    $key_a6a7 = { f5 c8 [2] d1 c6 [2] fa ea [2] d4 c8 [2] c0 d3 [2] cf c9 [2] d1 d4 [2] d3 d5 [2] c8 d3 [2] d4 d4 [2] c8 fb }

  condition:
    any of them
}