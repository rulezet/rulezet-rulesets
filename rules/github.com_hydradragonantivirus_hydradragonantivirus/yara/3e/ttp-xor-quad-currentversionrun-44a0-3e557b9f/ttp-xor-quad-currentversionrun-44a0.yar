rule TTP_XOR_QUAD_CurrentVersionRun_44a0 {
  strings:
    $key_44a0 = { 17 cf [2] 33 c1 [2] 18 ed [2] 36 cf [2] 22 d4 [2] 2d ce [2] 33 d3 [2] 31 d2 [2] 2a d4 [2] 36 d3 [2] 2a fc }

  condition:
    any of them
}