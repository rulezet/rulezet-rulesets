rule TTP_XOR_QUAD_CurrentVersionRun_6abd {
  strings:
    $key_6abd = { 39 d2 [2] 1d dc [2] 36 f0 [2] 18 d2 [2] 0c c9 [2] 03 d3 [2] 1d ce [2] 1f cf [2] 04 c9 [2] 18 ce [2] 04 e1 }

  condition:
    any of them
}