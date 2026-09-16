rule TTP_XOR_QUAD_CurrentVersionRun_9aa1 {
  strings:
    $key_9aa1 = { c9 ce [2] ed c0 [2] c6 ec [2] e8 ce [2] fc d5 [2] f3 cf [2] ed d2 [2] ef d3 [2] f4 d5 [2] e8 d2 [2] f4 fd }

  condition:
    any of them
}