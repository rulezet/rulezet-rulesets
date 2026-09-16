rule TTP_XOR_QUAD_CurrentVersionRun_54a0 {
  strings:
    $key_54a0 = { 07 cf [2] 23 c1 [2] 08 ed [2] 26 cf [2] 32 d4 [2] 3d ce [2] 23 d3 [2] 21 d2 [2] 3a d4 [2] 26 d3 [2] 3a fc }

  condition:
    any of them
}