rule TTP_XOR_QUAD_CurrentVersionRun_3abd {
  strings:
    $key_3abd = { 69 d2 [2] 4d dc [2] 66 f0 [2] 48 d2 [2] 5c c9 [2] 53 d3 [2] 4d ce [2] 4f cf [2] 54 c9 [2] 48 ce [2] 54 e1 }

  condition:
    any of them
}