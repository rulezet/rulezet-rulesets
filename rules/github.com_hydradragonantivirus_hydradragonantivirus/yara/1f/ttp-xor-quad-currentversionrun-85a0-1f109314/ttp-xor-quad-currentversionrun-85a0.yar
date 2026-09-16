rule TTP_XOR_QUAD_CurrentVersionRun_85a0 {
  strings:
    $key_85a0 = { d6 cf [2] f2 c1 [2] d9 ed [2] f7 cf [2] e3 d4 [2] ec ce [2] f2 d3 [2] f0 d2 [2] eb d4 [2] f7 d3 [2] eb fc }

  condition:
    any of them
}