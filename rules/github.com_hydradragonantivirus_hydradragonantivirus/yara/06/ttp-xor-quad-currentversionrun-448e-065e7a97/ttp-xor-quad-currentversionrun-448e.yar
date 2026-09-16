rule TTP_XOR_QUAD_CurrentVersionRun_448e {
  strings:
    $key_448e = { 17 e1 [2] 33 ef [2] 18 c3 [2] 36 e1 [2] 22 fa [2] 2d e0 [2] 33 fd [2] 31 fc [2] 2a fa [2] 36 fd [2] 2a d2 }

  condition:
    any of them
}