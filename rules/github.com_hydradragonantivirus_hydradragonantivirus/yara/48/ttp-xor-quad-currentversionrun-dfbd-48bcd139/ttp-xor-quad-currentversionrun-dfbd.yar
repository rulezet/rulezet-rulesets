rule TTP_XOR_QUAD_CurrentVersionRun_dfbd {
  strings:
    $key_dfbd = { 8c d2 [2] a8 dc [2] 83 f0 [2] ad d2 [2] b9 c9 [2] b6 d3 [2] a8 ce [2] aa cf [2] b1 c9 [2] ad ce [2] b1 e1 }

  condition:
    any of them
}