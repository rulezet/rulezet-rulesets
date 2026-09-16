rule TTP_XOR_QUAD_CurrentVersionRun_0ba1 {
  strings:
    $key_0ba1 = { 58 ce [2] 7c c0 [2] 57 ec [2] 79 ce [2] 6d d5 [2] 62 cf [2] 7c d2 [2] 7e d3 [2] 65 d5 [2] 79 d2 [2] 65 fd }

  condition:
    any of them
}