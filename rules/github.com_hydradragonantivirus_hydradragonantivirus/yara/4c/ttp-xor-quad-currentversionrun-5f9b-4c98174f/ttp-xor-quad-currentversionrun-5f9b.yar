rule TTP_XOR_QUAD_CurrentVersionRun_5f9b {
  strings:
    $key_5f9b = { 0c f4 [2] 28 fa [2] 03 d6 [2] 2d f4 [2] 39 ef [2] 36 f5 [2] 28 e8 [2] 2a e9 [2] 31 ef [2] 2d e8 [2] 31 c7 }

  condition:
    any of them
}