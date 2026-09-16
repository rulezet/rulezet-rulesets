rule TTP_XOR_QUAD_CurrentVersionRun_48a1 {
  strings:
    $key_48a1 = { 1b ce [2] 3f c0 [2] 14 ec [2] 3a ce [2] 2e d5 [2] 21 cf [2] 3f d2 [2] 3d d3 [2] 26 d5 [2] 3a d2 [2] 26 fd }

  condition:
    any of them
}