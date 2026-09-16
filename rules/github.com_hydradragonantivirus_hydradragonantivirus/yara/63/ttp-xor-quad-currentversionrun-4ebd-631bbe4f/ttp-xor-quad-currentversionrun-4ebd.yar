rule TTP_XOR_QUAD_CurrentVersionRun_4ebd {
  strings:
    $key_4ebd = { 1d d2 [2] 39 dc [2] 12 f0 [2] 3c d2 [2] 28 c9 [2] 27 d3 [2] 39 ce [2] 3b cf [2] 20 c9 [2] 3c ce [2] 20 e1 }

  condition:
    any of them
}