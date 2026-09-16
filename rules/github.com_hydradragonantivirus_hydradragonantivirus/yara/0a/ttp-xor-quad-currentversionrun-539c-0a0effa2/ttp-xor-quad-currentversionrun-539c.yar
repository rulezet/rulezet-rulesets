rule TTP_XOR_QUAD_CurrentVersionRun_539c {
  strings:
    $key_539c = { 00 f3 [2] 24 fd [2] 0f d1 [2] 21 f3 [2] 35 e8 [2] 3a f2 [2] 24 ef [2] 26 ee [2] 3d e8 [2] 21 ef [2] 3d c0 }

  condition:
    any of them
}