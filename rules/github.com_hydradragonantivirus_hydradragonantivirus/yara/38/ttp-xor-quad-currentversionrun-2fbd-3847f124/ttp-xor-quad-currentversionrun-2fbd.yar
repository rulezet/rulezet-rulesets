rule TTP_XOR_QUAD_CurrentVersionRun_2fbd {
  strings:
    $key_2fbd = { 7c d2 [2] 58 dc [2] 73 f0 [2] 5d d2 [2] 49 c9 [2] 46 d3 [2] 58 ce [2] 5a cf [2] 41 c9 [2] 5d ce [2] 41 e1 }

  condition:
    any of them
}