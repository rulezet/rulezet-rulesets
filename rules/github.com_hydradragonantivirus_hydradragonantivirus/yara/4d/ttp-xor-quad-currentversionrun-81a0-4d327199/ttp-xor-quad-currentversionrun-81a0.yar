rule TTP_XOR_QUAD_CurrentVersionRun_81a0 {
  strings:
    $key_81a0 = { d2 cf [2] f6 c1 [2] dd ed [2] f3 cf [2] e7 d4 [2] e8 ce [2] f6 d3 [2] f4 d2 [2] ef d4 [2] f3 d3 [2] ef fc }

  condition:
    any of them
}