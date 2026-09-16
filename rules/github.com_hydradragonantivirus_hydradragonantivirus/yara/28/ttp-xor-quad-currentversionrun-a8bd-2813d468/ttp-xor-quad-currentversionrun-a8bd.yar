rule TTP_XOR_QUAD_CurrentVersionRun_a8bd {
  strings:
    $key_a8bd = { fb d2 [2] df dc [2] f4 f0 [2] da d2 [2] ce c9 [2] c1 d3 [2] df ce [2] dd cf [2] c6 c9 [2] da ce [2] c6 e1 }

  condition:
    any of them
}