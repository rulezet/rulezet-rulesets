rule TTP_XOR_QUAD_CurrentVersionRun_6f9b {
  strings:
    $key_6f9b = { 3c f4 [2] 18 fa [2] 33 d6 [2] 1d f4 [2] 09 ef [2] 06 f5 [2] 18 e8 [2] 1a e9 [2] 01 ef [2] 1d e8 [2] 01 c7 }

  condition:
    any of them
}