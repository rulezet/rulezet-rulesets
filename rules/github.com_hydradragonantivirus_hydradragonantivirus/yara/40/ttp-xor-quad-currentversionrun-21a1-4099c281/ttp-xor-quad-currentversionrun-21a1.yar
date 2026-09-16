rule TTP_XOR_QUAD_CurrentVersionRun_21a1 {
  strings:
    $key_21a1 = { 72 ce [2] 56 c0 [2] 7d ec [2] 53 ce [2] 47 d5 [2] 48 cf [2] 56 d2 [2] 54 d3 [2] 4f d5 [2] 53 d2 [2] 4f fd }

  condition:
    any of them
}