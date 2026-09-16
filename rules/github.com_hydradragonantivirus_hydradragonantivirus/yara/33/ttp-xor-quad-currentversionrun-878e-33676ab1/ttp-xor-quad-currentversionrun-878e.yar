rule TTP_XOR_QUAD_CurrentVersionRun_878e {
  strings:
    $key_878e = { d4 e1 [2] f0 ef [2] db c3 [2] f5 e1 [2] e1 fa [2] ee e0 [2] f0 fd [2] f2 fc [2] e9 fa [2] f5 fd [2] e9 d2 }

  condition:
    any of them
}