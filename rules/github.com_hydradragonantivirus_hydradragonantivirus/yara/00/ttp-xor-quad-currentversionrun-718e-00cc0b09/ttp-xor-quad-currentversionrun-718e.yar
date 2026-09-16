rule TTP_XOR_QUAD_CurrentVersionRun_718e {
  strings:
    $key_718e = { 22 e1 [2] 06 ef [2] 2d c3 [2] 03 e1 [2] 17 fa [2] 18 e0 [2] 06 fd [2] 04 fc [2] 1f fa [2] 03 fd [2] 1f d2 }

  condition:
    any of them
}