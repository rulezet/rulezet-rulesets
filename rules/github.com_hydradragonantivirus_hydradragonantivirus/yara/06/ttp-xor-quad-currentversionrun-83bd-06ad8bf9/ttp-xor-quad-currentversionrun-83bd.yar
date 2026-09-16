rule TTP_XOR_QUAD_CurrentVersionRun_83bd {
  strings:
    $key_83bd = { d0 d2 [2] f4 dc [2] df f0 [2] f1 d2 [2] e5 c9 [2] ea d3 [2] f4 ce [2] f6 cf [2] ed c9 [2] f1 ce [2] ed e1 }

  condition:
    any of them
}