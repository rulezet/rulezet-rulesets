rule TTP_XOR_QUAD_CurrentVersionRun_14a0 {
  strings:
    $key_14a0 = { 47 cf [2] 63 c1 [2] 48 ed [2] 66 cf [2] 72 d4 [2] 7d ce [2] 63 d3 [2] 61 d2 [2] 7a d4 [2] 66 d3 [2] 7a fc }

  condition:
    any of them
}