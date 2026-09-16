rule TTP_XOR_QUAD_CurrentVersionRun_1abd {
  strings:
    $key_1abd = { 49 d2 [2] 6d dc [2] 46 f0 [2] 68 d2 [2] 7c c9 [2] 73 d3 [2] 6d ce [2] 6f cf [2] 74 c9 [2] 68 ce [2] 74 e1 }

  condition:
    any of them
}