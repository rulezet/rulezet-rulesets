rule TTP_XOR_QUAD_CurrentVersionRun_b5bd {
  strings:
    $key_b5bd = { e6 d2 [2] c2 dc [2] e9 f0 [2] c7 d2 [2] d3 c9 [2] dc d3 [2] c2 ce [2] c0 cf [2] db c9 [2] c7 ce [2] db e1 }

  condition:
    any of them
}