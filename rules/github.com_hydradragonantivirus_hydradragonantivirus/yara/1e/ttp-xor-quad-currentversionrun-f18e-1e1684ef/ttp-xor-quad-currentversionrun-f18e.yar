rule TTP_XOR_QUAD_CurrentVersionRun_f18e {
  strings:
    $key_f18e = { a2 e1 [2] 86 ef [2] ad c3 [2] 83 e1 [2] 97 fa [2] 98 e0 [2] 86 fd [2] 84 fc [2] 9f fa [2] 83 fd [2] 9f d2 }

  condition:
    any of them
}