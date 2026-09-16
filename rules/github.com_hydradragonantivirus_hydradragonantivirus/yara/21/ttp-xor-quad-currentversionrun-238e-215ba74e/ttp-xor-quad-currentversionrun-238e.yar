rule TTP_XOR_QUAD_CurrentVersionRun_238e {
  strings:
    $key_238e = { 70 e1 [2] 54 ef [2] 7f c3 [2] 51 e1 [2] 45 fa [2] 4a e0 [2] 54 fd [2] 56 fc [2] 4d fa [2] 51 fd [2] 4d d2 }

  condition:
    any of them
}