rule TTP_XOR_QUAD_CurrentVersionRun_018e {
  strings:
    $key_018e = { 52 e1 [2] 76 ef [2] 5d c3 [2] 73 e1 [2] 67 fa [2] 68 e0 [2] 76 fd [2] 74 fc [2] 6f fa [2] 73 fd [2] 6f d2 }

  condition:
    any of them
}