rule TTP_XOR_QUAD_CurrentVersionRun_91a1 {
  strings:
    $key_91a1 = { c2 ce [2] e6 c0 [2] cd ec [2] e3 ce [2] f7 d5 [2] f8 cf [2] e6 d2 [2] e4 d3 [2] ff d5 [2] e3 d2 [2] ff fd }

  condition:
    any of them
}