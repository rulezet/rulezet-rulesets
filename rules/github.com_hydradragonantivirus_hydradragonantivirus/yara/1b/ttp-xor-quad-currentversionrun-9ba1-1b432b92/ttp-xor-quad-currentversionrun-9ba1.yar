rule TTP_XOR_QUAD_CurrentVersionRun_9ba1 {
  strings:
    $key_9ba1 = { c8 ce [2] ec c0 [2] c7 ec [2] e9 ce [2] fd d5 [2] f2 cf [2] ec d2 [2] ee d3 [2] f5 d5 [2] e9 d2 [2] f5 fd }

  condition:
    any of them
}