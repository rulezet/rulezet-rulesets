rule TTP_XOR_QUAD_CurrentVersionRun_809b {
  strings:
    $key_809b = { d3 f4 [2] f7 fa [2] dc d6 [2] f2 f4 [2] e6 ef [2] e9 f5 [2] f7 e8 [2] f5 e9 [2] ee ef [2] f2 e8 [2] ee c7 }

  condition:
    any of them
}