rule TTP_XOR_QUAD_CurrentVersionRun_95a1 {
  strings:
    $key_95a1 = { c6 ce [2] e2 c0 [2] c9 ec [2] e7 ce [2] f3 d5 [2] fc cf [2] e2 d2 [2] e0 d3 [2] fb d5 [2] e7 d2 [2] fb fd }

  condition:
    any of them
}