rule TTP_XOR_QUAD_CurrentVersionRun_7abd {
  strings:
    $key_7abd = { 29 d2 [2] 0d dc [2] 26 f0 [2] 08 d2 [2] 1c c9 [2] 13 d3 [2] 0d ce [2] 0f cf [2] 14 c9 [2] 08 ce [2] 14 e1 }

  condition:
    any of them
}