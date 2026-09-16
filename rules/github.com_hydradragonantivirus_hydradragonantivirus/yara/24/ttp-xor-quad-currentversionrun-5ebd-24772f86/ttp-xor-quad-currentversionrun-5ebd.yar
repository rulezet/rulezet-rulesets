rule TTP_XOR_QUAD_CurrentVersionRun_5ebd {
  strings:
    $key_5ebd = { 0d d2 [2] 29 dc [2] 02 f0 [2] 2c d2 [2] 38 c9 [2] 37 d3 [2] 29 ce [2] 2b cf [2] 30 c9 [2] 2c ce [2] 30 e1 }

  condition:
    any of them
}