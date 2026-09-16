rule TTP_XOR_QUAD_CurrentVersionRun_539b {
  strings:
    $key_539b = { 00 f4 [2] 24 fa [2] 0f d6 [2] 21 f4 [2] 35 ef [2] 3a f5 [2] 24 e8 [2] 26 e9 [2] 3d ef [2] 21 e8 [2] 3d c7 }

  condition:
    any of them
}