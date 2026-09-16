rule TTP_XOR_QUAD_CurrentVersionRun_66a1 {
  strings:
    $key_66a1 = { 35 ce [2] 11 c0 [2] 3a ec [2] 14 ce [2] 00 d5 [2] 0f cf [2] 11 d2 [2] 13 d3 [2] 08 d5 [2] 14 d2 [2] 08 fd }

  condition:
    any of them
}