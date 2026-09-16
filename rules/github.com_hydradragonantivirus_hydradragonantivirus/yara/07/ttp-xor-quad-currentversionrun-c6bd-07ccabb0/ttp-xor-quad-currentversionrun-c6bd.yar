rule TTP_XOR_QUAD_CurrentVersionRun_c6bd {
  strings:
    $key_c6bd = { 95 d2 [2] b1 dc [2] 9a f0 [2] b4 d2 [2] a0 c9 [2] af d3 [2] b1 ce [2] b3 cf [2] a8 c9 [2] b4 ce [2] a8 e1 }

  condition:
    any of them
}