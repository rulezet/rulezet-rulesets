rule TTP_XOR_QUAD_CurrentVersionRun_a6a1 {
  strings:
    $key_a6a1 = { f5 ce [2] d1 c0 [2] fa ec [2] d4 ce [2] c0 d5 [2] cf cf [2] d1 d2 [2] d3 d3 [2] c8 d5 [2] d4 d2 [2] c8 fd }

  condition:
    any of them
}