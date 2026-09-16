rule TTP_XOR_QUAD_CurrentVersionRun_0fbd {
  strings:
    $key_0fbd = { 5c d2 [2] 78 dc [2] 53 f0 [2] 7d d2 [2] 69 c9 [2] 66 d3 [2] 78 ce [2] 7a cf [2] 61 c9 [2] 7d ce [2] 61 e1 }

  condition:
    any of them
}