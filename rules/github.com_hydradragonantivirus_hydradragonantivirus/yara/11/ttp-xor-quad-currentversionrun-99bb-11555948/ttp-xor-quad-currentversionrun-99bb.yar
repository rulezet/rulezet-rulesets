rule TTP_XOR_QUAD_CurrentVersionRun_99bb {
  strings:
    $key_99bb = { ca d4 [2] ee da [2] c5 f6 [2] eb d4 [2] ff cf [2] f0 d5 [2] ee c8 [2] ec c9 [2] f7 cf [2] eb c8 [2] f7 e7 }

  condition:
    any of them
}