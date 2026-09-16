rule TTP_XOR_QUAD_CurrentVersionRun_50a1 {
  strings:
    $key_50a1 = { 03 ce [2] 27 c0 [2] 0c ec [2] 22 ce [2] 36 d5 [2] 39 cf [2] 27 d2 [2] 25 d3 [2] 3e d5 [2] 22 d2 [2] 3e fd }

  condition:
    any of them
}