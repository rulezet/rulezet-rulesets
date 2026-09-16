rule TTP_XOR_QUAD_CurrentVersionRun_5da1 {
  strings:
    $key_5da1 = { 0e ce [2] 2a c0 [2] 01 ec [2] 2f ce [2] 3b d5 [2] 34 cf [2] 2a d2 [2] 28 d3 [2] 33 d5 [2] 2f d2 [2] 33 fd }

  condition:
    any of them
}