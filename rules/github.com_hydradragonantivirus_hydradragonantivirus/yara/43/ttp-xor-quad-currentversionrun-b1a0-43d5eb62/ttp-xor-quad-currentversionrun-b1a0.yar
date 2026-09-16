rule TTP_XOR_QUAD_CurrentVersionRun_b1a0 {
  strings:
    $key_b1a0 = { e2 cf [2] c6 c1 [2] ed ed [2] c3 cf [2] d7 d4 [2] d8 ce [2] c6 d3 [2] c4 d2 [2] df d4 [2] c3 d3 [2] df fc }

  condition:
    any of them
}