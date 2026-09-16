rule TTP_XOR_QUAD_CurrentVersionRun_27a1 {
  strings:
    $key_27a1 = { 74 ce [2] 50 c0 [2] 7b ec [2] 55 ce [2] 41 d5 [2] 4e cf [2] 50 d2 [2] 52 d3 [2] 49 d5 [2] 55 d2 [2] 49 fd }

  condition:
    any of them
}