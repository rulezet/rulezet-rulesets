rule TTP_XOR_QUAD_CurrentVersionRun_f8a1 {
  strings:
    $key_f8a1 = { ab ce [2] 8f c0 [2] a4 ec [2] 8a ce [2] 9e d5 [2] 91 cf [2] 8f d2 [2] 8d d3 [2] 96 d5 [2] 8a d2 [2] 96 fd }

  condition:
    any of them
}