rule TTP_XOR_QUAD_CurrentVersionRun_6e8e {
  strings:
    $key_6e8e = { 3d e1 [2] 19 ef [2] 32 c3 [2] 1c e1 [2] 08 fa [2] 07 e0 [2] 19 fd [2] 1b fc [2] 00 fa [2] 1c fd [2] 00 d2 }

  condition:
    any of them
}