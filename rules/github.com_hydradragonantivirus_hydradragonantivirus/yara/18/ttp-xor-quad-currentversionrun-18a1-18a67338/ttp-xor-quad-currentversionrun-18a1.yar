rule TTP_XOR_QUAD_CurrentVersionRun_18a1 {
  strings:
    $key_18a1 = { 4b ce [2] 6f c0 [2] 44 ec [2] 6a ce [2] 7e d5 [2] 71 cf [2] 6f d2 [2] 6d d3 [2] 76 d5 [2] 6a d2 [2] 76 fd }

  condition:
    any of them
}