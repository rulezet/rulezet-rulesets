rule TTP_XOR_QUAD_CurrentVersionRun_85bb {
  strings:
    $key_85bb = { d6 d4 [2] f2 da [2] d9 f6 [2] f7 d4 [2] e3 cf [2] ec d5 [2] f2 c8 [2] f0 c9 [2] eb cf [2] f7 c8 [2] eb e7 }

  condition:
    any of them
}