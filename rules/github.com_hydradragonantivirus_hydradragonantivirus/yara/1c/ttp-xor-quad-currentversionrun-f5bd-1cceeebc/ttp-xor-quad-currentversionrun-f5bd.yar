rule TTP_XOR_QUAD_CurrentVersionRun_f5bd {
  strings:
    $key_f5bd = { a6 d2 [2] 82 dc [2] a9 f0 [2] 87 d2 [2] 93 c9 [2] 9c d3 [2] 82 ce [2] 80 cf [2] 9b c9 [2] 87 ce [2] 9b e1 }

  condition:
    any of them
}