rule TTP_XOR_QUAD_CurrentVersionRun_538e {
  strings:
    $key_538e = { 00 e1 [2] 24 ef [2] 0f c3 [2] 21 e1 [2] 35 fa [2] 3a e0 [2] 24 fd [2] 26 fc [2] 3d fa [2] 21 fd [2] 3d d2 }

  condition:
    any of them
}