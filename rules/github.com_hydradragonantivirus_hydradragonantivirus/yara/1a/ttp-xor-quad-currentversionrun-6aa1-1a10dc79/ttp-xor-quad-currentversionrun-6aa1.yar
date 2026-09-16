rule TTP_XOR_QUAD_CurrentVersionRun_6aa1 {
  strings:
    $key_6aa1 = { 39 ce [2] 1d c0 [2] 36 ec [2] 18 ce [2] 0c d5 [2] 03 cf [2] 1d d2 [2] 1f d3 [2] 04 d5 [2] 18 d2 [2] 04 fd }

  condition:
    any of them
}