rule TTP_XOR_QUAD_CurrentVersionRun_96bd {
  strings:
    $key_96bd = { c5 d2 [2] e1 dc [2] ca f0 [2] e4 d2 [2] f0 c9 [2] ff d3 [2] e1 ce [2] e3 cf [2] f8 c9 [2] e4 ce [2] f8 e1 }

  condition:
    any of them
}