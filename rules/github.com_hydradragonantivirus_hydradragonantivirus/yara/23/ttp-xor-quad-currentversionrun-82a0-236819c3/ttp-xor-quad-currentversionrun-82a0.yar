rule TTP_XOR_QUAD_CurrentVersionRun_82a0 {
  strings:
    $key_82a0 = { d1 cf [2] f5 c1 [2] de ed [2] f0 cf [2] e4 d4 [2] eb ce [2] f5 d3 [2] f7 d2 [2] ec d4 [2] f0 d3 [2] ec fc }

  condition:
    any of them
}