rule TTP_XOR_QUAD_CurrentVersionRun_38a1 {
  strings:
    $key_38a1 = { 6b ce [2] 4f c0 [2] 64 ec [2] 4a ce [2] 5e d5 [2] 51 cf [2] 4f d2 [2] 4d d3 [2] 56 d5 [2] 4a d2 [2] 56 fd }

  condition:
    any of them
}