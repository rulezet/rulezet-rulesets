rule TTP_XOR_QUAD_CurrentVersionRun_0e9b {
  strings:
    $key_0e9b = { 5d f4 [2] 79 fa [2] 52 d6 [2] 7c f4 [2] 68 ef [2] 67 f5 [2] 79 e8 [2] 7b e9 [2] 60 ef [2] 7c e8 [2] 60 c7 }

  condition:
    any of them
}