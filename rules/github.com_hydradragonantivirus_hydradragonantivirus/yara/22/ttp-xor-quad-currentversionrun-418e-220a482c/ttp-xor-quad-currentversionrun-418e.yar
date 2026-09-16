rule TTP_XOR_QUAD_CurrentVersionRun_418e {
  strings:
    $key_418e = { 12 e1 [2] 36 ef [2] 1d c3 [2] 33 e1 [2] 27 fa [2] 28 e0 [2] 36 fd [2] 34 fc [2] 2f fa [2] 33 fd [2] 2f d2 }

  condition:
    any of them
}