rule TTP_XOR_QUAD_CurrentVersionRun_108e {
  strings:
    $key_108e = { 43 e1 [2] 67 ef [2] 4c c3 [2] 62 e1 [2] 76 fa [2] 79 e0 [2] 67 fd [2] 65 fc [2] 7e fa [2] 62 fd [2] 7e d2 }

  condition:
    any of them
}