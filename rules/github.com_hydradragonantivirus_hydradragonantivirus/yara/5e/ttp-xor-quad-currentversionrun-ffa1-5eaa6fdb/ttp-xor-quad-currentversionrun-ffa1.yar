rule TTP_XOR_QUAD_CurrentVersionRun_ffa1 {
  strings:
    $key_ffa1 = { ac ce [2] 88 c0 [2] a3 ec [2] 8d ce [2] 99 d5 [2] 96 cf [2] 88 d2 [2] 8a d3 [2] 91 d5 [2] 8d d2 [2] 91 fd }

  condition:
    any of them
}