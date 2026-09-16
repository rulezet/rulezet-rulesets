rule TTP_XOR_QUAD_CurrentVersionRun_6f8e {
  strings:
    $key_6f8e = { 3c e1 [2] 18 ef [2] 33 c3 [2] 1d e1 [2] 09 fa [2] 06 e0 [2] 18 fd [2] 1a fc [2] 01 fa [2] 1d fd [2] 01 d2 }

  condition:
    any of them
}