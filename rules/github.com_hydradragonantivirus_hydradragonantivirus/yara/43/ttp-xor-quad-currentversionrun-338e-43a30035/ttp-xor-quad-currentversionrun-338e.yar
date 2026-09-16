rule TTP_XOR_QUAD_CurrentVersionRun_338e {
  strings:
    $key_338e = { 60 e1 [2] 44 ef [2] 6f c3 [2] 41 e1 [2] 55 fa [2] 5a e0 [2] 44 fd [2] 46 fc [2] 5d fa [2] 41 fd [2] 5d d2 }

  condition:
    any of them
}