rule TTP_XOR_QUAD_CurrentVersionRun_8aa0 {
  strings:
    $key_8aa0 = { d9 cf [2] fd c1 [2] d6 ed [2] f8 cf [2] ec d4 [2] e3 ce [2] fd d3 [2] ff d2 [2] e4 d4 [2] f8 d3 [2] e4 fc }

  condition:
    any of them
}