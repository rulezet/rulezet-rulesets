rule TTP_XOR_QUAD_CurrentVersionRun_d1bd {
  strings:
    $key_d1bd = { 82 d2 [2] a6 dc [2] 8d f0 [2] a3 d2 [2] b7 c9 [2] b8 d3 [2] a6 ce [2] a4 cf [2] bf c9 [2] a3 ce [2] bf e1 }

  condition:
    any of them
}