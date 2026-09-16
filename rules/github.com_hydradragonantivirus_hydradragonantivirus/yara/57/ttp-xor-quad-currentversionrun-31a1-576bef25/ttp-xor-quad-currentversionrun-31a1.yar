rule TTP_XOR_QUAD_CurrentVersionRun_31a1 {
  strings:
    $key_31a1 = { 62 ce [2] 46 c0 [2] 6d ec [2] 43 ce [2] 57 d5 [2] 58 cf [2] 46 d2 [2] 44 d3 [2] 5f d5 [2] 43 d2 [2] 5f fd }

  condition:
    any of them
}