rule TTP_XOR_QUAD_CurrentVersionRun_83a1 {
  strings:
    $key_83a1 = { d0 ce [2] f4 c0 [2] df ec [2] f1 ce [2] e5 d5 [2] ea cf [2] f4 d2 [2] f6 d3 [2] ed d5 [2] f1 d2 [2] ed fd }

  condition:
    any of them
}