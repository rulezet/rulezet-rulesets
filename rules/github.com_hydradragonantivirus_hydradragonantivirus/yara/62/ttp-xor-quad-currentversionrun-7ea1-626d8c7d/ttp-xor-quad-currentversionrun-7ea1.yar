rule TTP_XOR_QUAD_CurrentVersionRun_7ea1 {
  strings:
    $key_7ea1 = { 2d ce [2] 09 c0 [2] 22 ec [2] 0c ce [2] 18 d5 [2] 17 cf [2] 09 d2 [2] 0b d3 [2] 10 d5 [2] 0c d2 [2] 10 fd }

  condition:
    any of them
}