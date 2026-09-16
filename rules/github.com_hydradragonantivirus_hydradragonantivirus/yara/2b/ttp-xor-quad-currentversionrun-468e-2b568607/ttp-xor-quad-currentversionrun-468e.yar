rule TTP_XOR_QUAD_CurrentVersionRun_468e {
  strings:
    $key_468e = { 15 e1 [2] 31 ef [2] 1a c3 [2] 34 e1 [2] 20 fa [2] 2f e0 [2] 31 fd [2] 33 fc [2] 28 fa [2] 34 fd [2] 28 d2 }

  condition:
    any of them
}