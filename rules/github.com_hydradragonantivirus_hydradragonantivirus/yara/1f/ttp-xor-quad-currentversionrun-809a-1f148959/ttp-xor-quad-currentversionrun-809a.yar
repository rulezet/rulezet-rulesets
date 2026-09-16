rule TTP_XOR_QUAD_CurrentVersionRun_809a {
  strings:
    $key_809a = { d3 f5 [2] f7 fb [2] dc d7 [2] f2 f5 [2] e6 ee [2] e9 f4 [2] f7 e9 [2] f5 e8 [2] ee ee [2] f2 e9 [2] ee c6 }

  condition:
    any of them
}