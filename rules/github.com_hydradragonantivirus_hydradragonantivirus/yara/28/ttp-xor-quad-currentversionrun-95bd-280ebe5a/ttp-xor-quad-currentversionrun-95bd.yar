rule TTP_XOR_QUAD_CurrentVersionRun_95bd {
  strings:
    $key_95bd = { c6 d2 [2] e2 dc [2] c9 f0 [2] e7 d2 [2] f3 c9 [2] fc d3 [2] e2 ce [2] e0 cf [2] fb c9 [2] e7 ce [2] fb e1 }

  condition:
    any of them
}