rule TTP_XOR_QUAD_CurrentVersionRun_d1a1 {
  strings:
    $key_d1a1 = { 82 ce [2] a6 c0 [2] 8d ec [2] a3 ce [2] b7 d5 [2] b8 cf [2] a6 d2 [2] a4 d3 [2] bf d5 [2] a3 d2 [2] bf fd }

  condition:
    any of them
}