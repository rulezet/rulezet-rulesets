rule TTP_XOR_QUAD_CurrentVersionRun_60a0 {
  strings:
    $key_60a0 = { 33 cf [2] 17 c1 [2] 3c ed [2] 12 cf [2] 06 d4 [2] 09 ce [2] 17 d3 [2] 15 d2 [2] 0e d4 [2] 12 d3 [2] 0e fc }

  condition:
    any of them
}