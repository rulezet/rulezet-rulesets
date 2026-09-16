rule TTP_XOR_QUAD_CurrentVersionRun_29a1 {
  strings:
    $key_29a1 = { 7a ce [2] 5e c0 [2] 75 ec [2] 5b ce [2] 4f d5 [2] 40 cf [2] 5e d2 [2] 5c d3 [2] 47 d5 [2] 5b d2 [2] 47 fd }

  condition:
    any of them
}