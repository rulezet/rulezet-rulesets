rule TTP_XOR_QUAD_CurrentVersionRun_04a0 {
  strings:
    $key_04a0 = { 57 cf [2] 73 c1 [2] 58 ed [2] 76 cf [2] 62 d4 [2] 6d ce [2] 73 d3 [2] 71 d2 [2] 6a d4 [2] 76 d3 [2] 6a fc }

  condition:
    any of them
}