rule TTP_XOR_QUAD_CurrentVersionRun_92bb {
  strings:
    $key_92bb = { c1 d4 [2] e5 da [2] ce f6 [2] e0 d4 [2] f4 cf [2] fb d5 [2] e5 c8 [2] e7 c9 [2] fc cf [2] e0 c8 [2] fc e7 }

  condition:
    any of them
}