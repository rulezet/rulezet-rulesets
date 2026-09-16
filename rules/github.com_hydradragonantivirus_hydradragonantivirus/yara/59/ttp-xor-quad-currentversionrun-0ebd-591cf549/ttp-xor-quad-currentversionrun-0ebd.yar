rule TTP_XOR_QUAD_CurrentVersionRun_0ebd {
  strings:
    $key_0ebd = { 5d d2 [2] 79 dc [2] 52 f0 [2] 7c d2 [2] 68 c9 [2] 67 d3 [2] 79 ce [2] 7b cf [2] 60 c9 [2] 7c ce [2] 60 e1 }

  condition:
    any of them
}