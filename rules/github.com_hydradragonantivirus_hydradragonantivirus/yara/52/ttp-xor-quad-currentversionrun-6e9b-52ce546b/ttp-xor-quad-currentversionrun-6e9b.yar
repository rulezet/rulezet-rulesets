rule TTP_XOR_QUAD_CurrentVersionRun_6e9b {
  strings:
    $key_6e9b = { 3d f4 [2] 19 fa [2] 32 d6 [2] 1c f4 [2] 08 ef [2] 07 f5 [2] 19 e8 [2] 1b e9 [2] 00 ef [2] 1c e8 [2] 00 c7 }

  condition:
    any of them
}