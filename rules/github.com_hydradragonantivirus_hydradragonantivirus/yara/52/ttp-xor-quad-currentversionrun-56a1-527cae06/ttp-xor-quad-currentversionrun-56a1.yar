rule TTP_XOR_QUAD_CurrentVersionRun_56a1 {
  strings:
    $key_56a1 = { 05 ce [2] 21 c0 [2] 0a ec [2] 24 ce [2] 30 d5 [2] 3f cf [2] 21 d2 [2] 23 d3 [2] 38 d5 [2] 24 d2 [2] 38 fd }

  condition:
    any of them
}