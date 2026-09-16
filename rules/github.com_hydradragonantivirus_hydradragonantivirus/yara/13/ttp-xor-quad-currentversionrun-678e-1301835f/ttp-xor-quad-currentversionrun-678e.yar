rule TTP_XOR_QUAD_CurrentVersionRun_678e {
  strings:
    $key_678e = { 34 e1 [2] 10 ef [2] 3b c3 [2] 15 e1 [2] 01 fa [2] 0e e0 [2] 10 fd [2] 12 fc [2] 09 fa [2] 15 fd [2] 09 d2 }

  condition:
    any of them
}