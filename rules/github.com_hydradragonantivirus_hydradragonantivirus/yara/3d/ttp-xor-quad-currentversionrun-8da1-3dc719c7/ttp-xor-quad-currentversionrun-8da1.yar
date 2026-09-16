rule TTP_XOR_QUAD_CurrentVersionRun_8da1 {
  strings:
    $key_8da1 = { de ce [2] fa c0 [2] d1 ec [2] ff ce [2] eb d5 [2] e4 cf [2] fa d2 [2] f8 d3 [2] e3 d5 [2] ff d2 [2] e3 fd }

  condition:
    any of them
}