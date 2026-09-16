rule TTP_XOR_QUAD_CurrentVersionRun_69a1 {
  strings:
    $key_69a1 = { 3a ce [2] 1e c0 [2] 35 ec [2] 1b ce [2] 0f d5 [2] 00 cf [2] 1e d2 [2] 1c d3 [2] 07 d5 [2] 1b d2 [2] 07 fd }

  condition:
    any of them
}