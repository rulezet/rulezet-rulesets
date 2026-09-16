rule TTP_XOR_QUAD_CurrentVersionRun_70a1 {
  strings:
    $key_70a1 = { 23 ce [2] 07 c0 [2] 2c ec [2] 02 ce [2] 16 d5 [2] 19 cf [2] 07 d2 [2] 05 d3 [2] 1e d5 [2] 02 d2 [2] 1e fd }

  condition:
    any of them
}