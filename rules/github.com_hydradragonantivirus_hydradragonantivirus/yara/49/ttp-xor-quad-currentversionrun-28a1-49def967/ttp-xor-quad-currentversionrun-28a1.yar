rule TTP_XOR_QUAD_CurrentVersionRun_28a1 {
  strings:
    $key_28a1 = { 7b ce [2] 5f c0 [2] 74 ec [2] 5a ce [2] 4e d5 [2] 41 cf [2] 5f d2 [2] 5d d3 [2] 46 d5 [2] 5a d2 [2] 46 fd }

  condition:
    any of them
}