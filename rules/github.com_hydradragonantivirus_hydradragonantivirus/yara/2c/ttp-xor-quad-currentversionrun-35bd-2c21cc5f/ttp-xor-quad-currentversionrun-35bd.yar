rule TTP_XOR_QUAD_CurrentVersionRun_35bd {
  strings:
    $key_35bd = { 66 d2 [2] 42 dc [2] 69 f0 [2] 47 d2 [2] 53 c9 [2] 5c d3 [2] 42 ce [2] 40 cf [2] 5b c9 [2] 47 ce [2] 5b e1 }

  condition:
    any of them
}