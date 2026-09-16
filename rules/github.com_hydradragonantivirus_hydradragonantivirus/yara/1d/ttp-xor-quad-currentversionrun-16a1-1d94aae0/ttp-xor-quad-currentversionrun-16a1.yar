rule TTP_XOR_QUAD_CurrentVersionRun_16a1 {
  strings:
    $key_16a1 = { 45 ce [2] 61 c0 [2] 4a ec [2] 64 ce [2] 70 d5 [2] 7f cf [2] 61 d2 [2] 63 d3 [2] 78 d5 [2] 64 d2 [2] 78 fd }

  condition:
    any of them
}