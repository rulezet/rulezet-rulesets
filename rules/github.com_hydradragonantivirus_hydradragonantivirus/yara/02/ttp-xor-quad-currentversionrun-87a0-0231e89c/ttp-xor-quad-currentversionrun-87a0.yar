rule TTP_XOR_QUAD_CurrentVersionRun_87a0 {
  strings:
    $key_87a0 = { d4 cf [2] f0 c1 [2] db ed [2] f5 cf [2] e1 d4 [2] ee ce [2] f0 d3 [2] f2 d2 [2] e9 d4 [2] f5 d3 [2] e9 fc }

  condition:
    any of them
}