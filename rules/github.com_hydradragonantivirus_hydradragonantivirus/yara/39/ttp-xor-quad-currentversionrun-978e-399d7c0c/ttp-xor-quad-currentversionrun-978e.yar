rule TTP_XOR_QUAD_CurrentVersionRun_978e {
  strings:
    $key_978e = { c4 e1 [2] e0 ef [2] cb c3 [2] e5 e1 [2] f1 fa [2] fe e0 [2] e0 fd [2] e2 fc [2] f9 fa [2] e5 fd [2] f9 d2 }

  condition:
    any of them
}