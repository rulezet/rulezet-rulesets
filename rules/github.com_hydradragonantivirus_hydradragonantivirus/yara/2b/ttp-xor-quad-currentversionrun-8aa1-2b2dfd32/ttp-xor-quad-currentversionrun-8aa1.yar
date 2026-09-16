rule TTP_XOR_QUAD_CurrentVersionRun_8aa1 {
  strings:
    $key_8aa1 = { d9 ce [2] fd c0 [2] d6 ec [2] f8 ce [2] ec d5 [2] e3 cf [2] fd d2 [2] ff d3 [2] e4 d5 [2] f8 d2 [2] e4 fd }

  condition:
    any of them
}