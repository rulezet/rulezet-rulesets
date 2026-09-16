rule TTP_XOR_QUAD_CurrentVersionRun_d6a0 {
  strings:
    $key_d6a0 = { 85 cf [2] a1 c1 [2] 8a ed [2] a4 cf [2] b0 d4 [2] bf ce [2] a1 d3 [2] a3 d2 [2] b8 d4 [2] a4 d3 [2] b8 fc }

  condition:
    any of them
}