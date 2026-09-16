rule TTP_XOR_QUAD_CurrentVersionRun_49a1 {
  strings:
    $key_49a1 = { 1a ce [2] 3e c0 [2] 15 ec [2] 3b ce [2] 2f d5 [2] 20 cf [2] 3e d2 [2] 3c d3 [2] 27 d5 [2] 3b d2 [2] 27 fd }

  condition:
    any of them
}