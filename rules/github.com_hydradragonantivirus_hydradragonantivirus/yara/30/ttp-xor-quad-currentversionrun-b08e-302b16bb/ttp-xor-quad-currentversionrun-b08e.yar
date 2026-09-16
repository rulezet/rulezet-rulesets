rule TTP_XOR_QUAD_CurrentVersionRun_b08e {
  strings:
    $key_b08e = { e3 e1 [2] c7 ef [2] ec c3 [2] c2 e1 [2] d6 fa [2] d9 e0 [2] c7 fd [2] c5 fc [2] de fa [2] c2 fd [2] de d2 }

  condition:
    any of them
}