rule TTP_XOR_QUAD_CurrentVersionRun_59a1 {
  strings:
    $key_59a1 = { 0a ce [2] 2e c0 [2] 05 ec [2] 2b ce [2] 3f d5 [2] 30 cf [2] 2e d2 [2] 2c d3 [2] 37 d5 [2] 2b d2 [2] 37 fd }

  condition:
    any of them
}