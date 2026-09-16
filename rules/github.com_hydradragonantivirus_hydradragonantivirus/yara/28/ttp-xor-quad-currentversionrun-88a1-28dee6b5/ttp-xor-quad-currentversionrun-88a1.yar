rule TTP_XOR_QUAD_CurrentVersionRun_88a1 {
  strings:
    $key_88a1 = { db ce [2] ff c0 [2] d4 ec [2] fa ce [2] ee d5 [2] e1 cf [2] ff d2 [2] fd d3 [2] e6 d5 [2] fa d2 [2] e6 fd }

  condition:
    any of them
}