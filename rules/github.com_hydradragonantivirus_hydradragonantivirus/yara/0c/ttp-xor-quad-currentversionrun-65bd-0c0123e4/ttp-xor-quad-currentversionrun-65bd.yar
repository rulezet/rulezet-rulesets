rule TTP_XOR_QUAD_CurrentVersionRun_65bd {
  strings:
    $key_65bd = { 36 d2 [2] 12 dc [2] 39 f0 [2] 17 d2 [2] 03 c9 [2] 0c d3 [2] 12 ce [2] 10 cf [2] 0b c9 [2] 17 ce [2] 0b e1 }

  condition:
    any of them
}