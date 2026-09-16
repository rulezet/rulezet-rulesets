rule TTP_XOR_QUAD_CurrentVersionRun_46a1 {
  strings:
    $key_46a1 = { 15 ce [2] 31 c0 [2] 1a ec [2] 34 ce [2] 20 d5 [2] 2f cf [2] 31 d2 [2] 33 d3 [2] 28 d5 [2] 34 d2 [2] 28 fd }

  condition:
    any of them
}