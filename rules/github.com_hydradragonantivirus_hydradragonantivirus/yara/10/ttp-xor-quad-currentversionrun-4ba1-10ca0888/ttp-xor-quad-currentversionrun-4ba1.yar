rule TTP_XOR_QUAD_CurrentVersionRun_4ba1 {
  strings:
    $key_4ba1 = { 18 ce [2] 3c c0 [2] 17 ec [2] 39 ce [2] 2d d5 [2] 22 cf [2] 3c d2 [2] 3e d3 [2] 25 d5 [2] 39 d2 [2] 25 fd }

  condition:
    any of them
}