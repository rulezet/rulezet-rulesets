rule TTP_XOR_QUAD_CurrentVersionRun_3e9b {
  strings:
    $key_3e9b = { 6d f4 [2] 49 fa [2] 62 d6 [2] 4c f4 [2] 58 ef [2] 57 f5 [2] 49 e8 [2] 4b e9 [2] 50 ef [2] 4c e8 [2] 50 c7 }

  condition:
    any of them
}