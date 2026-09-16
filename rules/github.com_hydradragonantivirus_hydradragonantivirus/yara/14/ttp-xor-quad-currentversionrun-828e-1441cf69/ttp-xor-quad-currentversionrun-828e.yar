rule TTP_XOR_QUAD_CurrentVersionRun_828e {
  strings:
    $key_828e = { d1 e1 [2] f5 ef [2] de c3 [2] f0 e1 [2] e4 fa [2] eb e0 [2] f5 fd [2] f7 fc [2] ec fa [2] f0 fd [2] ec d2 }

  condition:
    any of them
}