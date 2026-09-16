rule TTP_XOR_QUAD_CurrentVersionRun_65a1 {
  strings:
    $key_65a1 = { 36 ce [2] 12 c0 [2] 39 ec [2] 17 ce [2] 03 d5 [2] 0c cf [2] 12 d2 [2] 10 d3 [2] 0b d5 [2] 17 d2 [2] 0b fd }

  condition:
    any of them
}