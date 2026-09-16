rule TTP_XOR_QUAD_CurrentVersionRun_96bb {
  strings:
    $key_96bb = { c5 d4 [2] e1 da [2] ca f6 [2] e4 d4 [2] f0 cf [2] ff d5 [2] e1 c8 [2] e3 c9 [2] f8 cf [2] e4 c8 [2] f8 e7 }

  condition:
    any of them
}