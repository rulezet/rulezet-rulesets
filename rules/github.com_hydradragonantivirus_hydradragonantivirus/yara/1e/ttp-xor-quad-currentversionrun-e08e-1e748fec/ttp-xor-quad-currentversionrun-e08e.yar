rule TTP_XOR_QUAD_CurrentVersionRun_e08e {
  strings:
    $key_e08e = { b3 e1 [2] 97 ef [2] bc c3 [2] 92 e1 [2] 86 fa [2] 89 e0 [2] 97 fd [2] 95 fc [2] 8e fa [2] 92 fd [2] 8e d2 }

  condition:
    any of them
}