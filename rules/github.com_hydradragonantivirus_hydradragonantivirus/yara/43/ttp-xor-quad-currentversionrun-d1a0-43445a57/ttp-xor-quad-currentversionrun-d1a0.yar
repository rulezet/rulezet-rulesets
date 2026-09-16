rule TTP_XOR_QUAD_CurrentVersionRun_d1a0 {
  strings:
    $key_d1a0 = { 82 cf [2] a6 c1 [2] 8d ed [2] a3 cf [2] b7 d4 [2] b8 ce [2] a6 d3 [2] a4 d2 [2] bf d4 [2] a3 d3 [2] bf fc }

  condition:
    any of them
}