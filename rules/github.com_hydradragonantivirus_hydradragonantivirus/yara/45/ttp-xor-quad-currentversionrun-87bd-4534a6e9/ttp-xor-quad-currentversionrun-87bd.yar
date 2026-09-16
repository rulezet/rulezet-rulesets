rule TTP_XOR_QUAD_CurrentVersionRun_87bd {
  strings:
    $key_87bd = { d4 d2 [2] f0 dc [2] db f0 [2] f5 d2 [2] e1 c9 [2] ee d3 [2] f0 ce [2] f2 cf [2] e9 c9 [2] f5 ce [2] e9 e1 }

  condition:
    any of them
}