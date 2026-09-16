rule TTP_XOR_QUAD_CurrentVersionRun_2ea1 {
  strings:
    $key_2ea1 = { 7d ce [2] 59 c0 [2] 72 ec [2] 5c ce [2] 48 d5 [2] 47 cf [2] 59 d2 [2] 5b d3 [2] 40 d5 [2] 5c d2 [2] 40 fd }

  condition:
    any of them
}