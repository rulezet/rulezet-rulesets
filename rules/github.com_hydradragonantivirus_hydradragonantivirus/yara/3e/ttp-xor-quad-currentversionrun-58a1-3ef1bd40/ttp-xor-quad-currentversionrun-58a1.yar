rule TTP_XOR_QUAD_CurrentVersionRun_58a1 {
  strings:
    $key_58a1 = { 0b ce [2] 2f c0 [2] 04 ec [2] 2a ce [2] 3e d5 [2] 31 cf [2] 2f d2 [2] 2d d3 [2] 36 d5 [2] 2a d2 [2] 36 fd }

  condition:
    any of them
}