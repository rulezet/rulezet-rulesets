rule TTP_XOR_QUAD_CurrentVersionRun_dea1 {
  strings:
    $key_dea1 = { 8d ce [2] a9 c0 [2] 82 ec [2] ac ce [2] b8 d5 [2] b7 cf [2] a9 d2 [2] ab d3 [2] b0 d5 [2] ac d2 [2] b0 fd }

  condition:
    any of them
}