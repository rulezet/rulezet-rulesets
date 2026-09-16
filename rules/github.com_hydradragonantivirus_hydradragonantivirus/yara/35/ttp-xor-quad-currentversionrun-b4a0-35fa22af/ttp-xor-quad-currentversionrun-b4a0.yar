rule TTP_XOR_QUAD_CurrentVersionRun_b4a0 {
  strings:
    $key_b4a0 = { e7 cf [2] c3 c1 [2] e8 ed [2] c6 cf [2] d2 d4 [2] dd ce [2] c3 d3 [2] c1 d2 [2] da d4 [2] c6 d3 [2] da fc }

  condition:
    any of them
}