rule TTP_XOR_QUAD_CurrentVersionRun_86bd {
  strings:
    $key_86bd = { d5 d2 [2] f1 dc [2] da f0 [2] f4 d2 [2] e0 c9 [2] ef d3 [2] f1 ce [2] f3 cf [2] e8 c9 [2] f4 ce [2] e8 e1 }

  condition:
    any of them
}