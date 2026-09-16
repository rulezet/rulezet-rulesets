rule TTP_XOR_QUAD_CurrentVersionRun_1fbd {
  strings:
    $key_1fbd = { 4c d2 [2] 68 dc [2] 43 f0 [2] 6d d2 [2] 79 c9 [2] 76 d3 [2] 68 ce [2] 6a cf [2] 71 c9 [2] 6d ce [2] 71 e1 }

  condition:
    any of them
}