rule TTP_XOR_QUAD_CurrentVersionRun_eca1 {
  strings:
    $key_eca1 = { bf ce [2] 9b c0 [2] b0 ec [2] 9e ce [2] 8a d5 [2] 85 cf [2] 9b d2 [2] 99 d3 [2] 82 d5 [2] 9e d2 [2] 82 fd }

  condition:
    any of them
}