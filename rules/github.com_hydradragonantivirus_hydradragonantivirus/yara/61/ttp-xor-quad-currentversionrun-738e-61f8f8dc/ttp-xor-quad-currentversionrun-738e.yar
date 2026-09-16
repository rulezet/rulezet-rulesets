rule TTP_XOR_QUAD_CurrentVersionRun_738e {
  strings:
    $key_738e = { 20 e1 [2] 04 ef [2] 2f c3 [2] 01 e1 [2] 15 fa [2] 1a e0 [2] 04 fd [2] 06 fc [2] 1d fa [2] 01 fd [2] 1d d2 }

  condition:
    any of them
}