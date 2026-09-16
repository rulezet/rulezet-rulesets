rule TTP_XOR_QUAD_CurrentVersionRun_1fa1 {
  strings:
    $key_1fa1 = { 4c ce [2] 68 c0 [2] 43 ec [2] 6d ce [2] 79 d5 [2] 76 cf [2] 68 d2 [2] 6a d3 [2] 71 d5 [2] 6d d2 [2] 71 fd }

  condition:
    any of them
}