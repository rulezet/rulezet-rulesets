rule TTP_XOR_QUAD_CurrentVersionRun_809d {
  strings:
    $key_809d = { d3 f2 [2] f7 fc [2] dc d0 [2] f2 f2 [2] e6 e9 [2] e9 f3 [2] f7 ee [2] f5 ef [2] ee e9 [2] f2 ee [2] ee c1 }

  condition:
    any of them
}