rule TTP_XOR_QUAD_CurrentVersionRun_9dbd {
  strings:
    $key_9dbd = { ce d2 [2] ea dc [2] c1 f0 [2] ef d2 [2] fb c9 [2] f4 d3 [2] ea ce [2] e8 cf [2] f3 c9 [2] ef ce [2] f3 e1 }

  condition:
    any of them
}