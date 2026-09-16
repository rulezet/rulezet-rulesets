rule TTP_XOR_QUAD_CurrentVersionRun_d6bd {
  strings:
    $key_d6bd = { 85 d2 [2] a1 dc [2] 8a f0 [2] a4 d2 [2] b0 c9 [2] bf d3 [2] a1 ce [2] a3 cf [2] b8 c9 [2] a4 ce [2] b8 e1 }

  condition:
    any of them
}