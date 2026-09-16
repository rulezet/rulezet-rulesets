rule TTP_XOR_QUAD_CurrentVersionRun_4abd {
  strings:
    $key_4abd = { 19 d2 [2] 3d dc [2] 16 f0 [2] 38 d2 [2] 2c c9 [2] 23 d3 [2] 3d ce [2] 3f cf [2] 24 c9 [2] 38 ce [2] 24 e1 }

  condition:
    any of them
}