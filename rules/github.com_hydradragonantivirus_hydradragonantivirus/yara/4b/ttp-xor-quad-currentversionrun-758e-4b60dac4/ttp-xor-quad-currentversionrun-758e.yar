rule TTP_XOR_QUAD_CurrentVersionRun_758e {
  strings:
    $key_758e = { 26 e1 [2] 02 ef [2] 29 c3 [2] 07 e1 [2] 13 fa [2] 1c e0 [2] 02 fd [2] 00 fc [2] 1b fa [2] 07 fd [2] 1b d2 }

  condition:
    any of them
}