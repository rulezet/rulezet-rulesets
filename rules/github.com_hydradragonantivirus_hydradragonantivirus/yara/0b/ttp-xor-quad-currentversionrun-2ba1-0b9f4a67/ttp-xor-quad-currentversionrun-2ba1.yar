rule TTP_XOR_QUAD_CurrentVersionRun_2ba1 {
  strings:
    $key_2ba1 = { 78 ce [2] 5c c0 [2] 77 ec [2] 59 ce [2] 4d d5 [2] 42 cf [2] 5c d2 [2] 5e d3 [2] 45 d5 [2] 59 d2 [2] 45 fd }

  condition:
    any of them
}