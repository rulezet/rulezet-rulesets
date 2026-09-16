rule TTP_XOR_QUAD_CurrentVersionRun_60a1 {
  strings:
    $key_60a1 = { 33 ce [2] 17 c0 [2] 3c ec [2] 12 ce [2] 06 d5 [2] 09 cf [2] 17 d2 [2] 15 d3 [2] 0e d5 [2] 12 d2 [2] 0e fd }

  condition:
    any of them
}