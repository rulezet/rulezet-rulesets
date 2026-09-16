rule TTP_XOR_QUAD_CurrentVersionRun_cf8e {
  strings:
    $key_cf8e = { 9c e1 [2] b8 ef [2] 93 c3 [2] bd e1 [2] a9 fa [2] a6 e0 [2] b8 fd [2] ba fc [2] a1 fa [2] bd fd [2] a1 d2 }

  condition:
    any of them
}