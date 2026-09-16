rule TTP_XOR_QUAD_CurrentVersionRun_0abd {
  strings:
    $key_0abd = { 59 d2 [2] 7d dc [2] 56 f0 [2] 78 d2 [2] 6c c9 [2] 63 d3 [2] 7d ce [2] 7f cf [2] 64 c9 [2] 78 ce [2] 64 e1 }

  condition:
    any of them
}