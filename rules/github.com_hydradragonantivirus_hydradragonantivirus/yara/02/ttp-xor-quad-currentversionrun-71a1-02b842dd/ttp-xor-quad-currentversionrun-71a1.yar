rule TTP_XOR_QUAD_CurrentVersionRun_71a1 {
  strings:
    $key_71a1 = { 22 ce [2] 06 c0 [2] 2d ec [2] 03 ce [2] 17 d5 [2] 18 cf [2] 06 d2 [2] 04 d3 [2] 1f d5 [2] 03 d2 [2] 1f fd }

  condition:
    any of them
}