rule TTP_XOR_QUAD_CurrentVersionRun_96a0 {
  strings:
    $key_96a0 = { c5 cf [2] e1 c1 [2] ca ed [2] e4 cf [2] f0 d4 [2] ff ce [2] e1 d3 [2] e3 d2 [2] f8 d4 [2] e4 d3 [2] f8 fc }

  condition:
    any of them
}