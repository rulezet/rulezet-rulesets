rule TTP_XOR_QUAD_CurrentVersionRun_968e {
  strings:
    $key_968e = { c5 e1 [2] e1 ef [2] ca c3 [2] e4 e1 [2] f0 fa [2] ff e0 [2] e1 fd [2] e3 fc [2] f8 fa [2] e4 fd [2] f8 d2 }

  condition:
    any of them
}