rule TTP_XOR_QUAD_CurrentVersionRun_938e {
  strings:
    $key_938e = { c0 e1 [2] e4 ef [2] cf c3 [2] e1 e1 [2] f5 fa [2] fa e0 [2] e4 fd [2] e6 fc [2] fd fa [2] e1 fd [2] fd d2 }

  condition:
    any of them
}