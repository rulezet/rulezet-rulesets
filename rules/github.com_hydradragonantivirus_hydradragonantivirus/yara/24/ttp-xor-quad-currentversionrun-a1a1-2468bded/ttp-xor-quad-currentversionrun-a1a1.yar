rule TTP_XOR_QUAD_CurrentVersionRun_a1a1 {
  strings:
    $key_a1a1 = { f2 ce [2] d6 c0 [2] fd ec [2] d3 ce [2] c7 d5 [2] c8 cf [2] d6 d2 [2] d4 d3 [2] cf d5 [2] d3 d2 [2] cf fd }

  condition:
    any of them
}