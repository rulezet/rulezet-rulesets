rule TTP_XOR_QUAD_CurrentVersionRun_09a1 {
  strings:
    $key_09a1 = { 5a ce [2] 7e c0 [2] 55 ec [2] 7b ce [2] 6f d5 [2] 60 cf [2] 7e d2 [2] 7c d3 [2] 67 d5 [2] 7b d2 [2] 67 fd }

  condition:
    any of them
}