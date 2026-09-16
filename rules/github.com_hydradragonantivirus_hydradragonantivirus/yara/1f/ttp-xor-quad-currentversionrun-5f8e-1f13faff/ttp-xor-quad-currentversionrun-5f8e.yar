rule TTP_XOR_QUAD_CurrentVersionRun_5f8e {
  strings:
    $key_5f8e = { 0c e1 [2] 28 ef [2] 03 c3 [2] 2d e1 [2] 39 fa [2] 36 e0 [2] 28 fd [2] 2a fc [2] 31 fa [2] 2d fd [2] 31 d2 }

  condition:
    any of them
}