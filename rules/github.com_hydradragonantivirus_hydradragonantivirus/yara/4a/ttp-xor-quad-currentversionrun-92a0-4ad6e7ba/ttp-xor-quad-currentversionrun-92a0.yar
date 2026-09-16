rule TTP_XOR_QUAD_CurrentVersionRun_92a0 {
  strings:
    $key_92a0 = { c1 cf [2] e5 c1 [2] ce ed [2] e0 cf [2] f4 d4 [2] fb ce [2] e5 d3 [2] e7 d2 [2] fc d4 [2] e0 d3 [2] fc fc }

  condition:
    any of them
}