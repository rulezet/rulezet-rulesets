rule TTP_XOR_QUAD_CurrentVersionRun_b2bd {
  strings:
    $key_b2bd = { e1 d2 [2] c5 dc [2] ee f0 [2] c0 d2 [2] d4 c9 [2] db d3 [2] c5 ce [2] c7 cf [2] dc c9 [2] c0 ce [2] dc e1 }

  condition:
    any of them
}