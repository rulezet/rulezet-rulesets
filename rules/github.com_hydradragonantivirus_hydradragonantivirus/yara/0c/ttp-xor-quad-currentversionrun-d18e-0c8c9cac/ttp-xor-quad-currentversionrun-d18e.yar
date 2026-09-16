rule TTP_XOR_QUAD_CurrentVersionRun_d18e {
  strings:
    $key_d18e = { 82 e1 [2] a6 ef [2] 8d c3 [2] a3 e1 [2] b7 fa [2] b8 e0 [2] a6 fd [2] a4 fc [2] bf fa [2] a3 fd [2] bf d2 }

  condition:
    any of them
}