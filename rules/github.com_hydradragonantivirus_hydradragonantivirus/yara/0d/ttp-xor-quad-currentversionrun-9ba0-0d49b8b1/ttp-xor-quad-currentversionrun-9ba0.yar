rule TTP_XOR_QUAD_CurrentVersionRun_9ba0 {
  strings:
    $key_9ba0 = { c8 cf [2] ec c1 [2] c7 ed [2] e9 cf [2] fd d4 [2] f2 ce [2] ec d3 [2] ee d2 [2] f5 d4 [2] e9 d3 [2] f5 fc }

  condition:
    any of them
}