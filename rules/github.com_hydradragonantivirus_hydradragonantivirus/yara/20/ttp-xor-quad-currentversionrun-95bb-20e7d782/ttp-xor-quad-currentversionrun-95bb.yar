rule TTP_XOR_QUAD_CurrentVersionRun_95bb {
  strings:
    $key_95bb = { c6 d4 [2] e2 da [2] c9 f6 [2] e7 d4 [2] f3 cf [2] fc d5 [2] e2 c8 [2] e0 c9 [2] fb cf [2] e7 c8 [2] fb e7 }

  condition:
    any of them
}