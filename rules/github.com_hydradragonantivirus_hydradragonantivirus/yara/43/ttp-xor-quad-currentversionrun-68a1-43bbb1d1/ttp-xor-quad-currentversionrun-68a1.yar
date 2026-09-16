rule TTP_XOR_QUAD_CurrentVersionRun_68a1 {
  strings:
    $key_68a1 = { 3b ce [2] 1f c0 [2] 34 ec [2] 1a ce [2] 0e d5 [2] 01 cf [2] 1f d2 [2] 1d d3 [2] 06 d5 [2] 1a d2 [2] 06 fd }

  condition:
    any of them
}