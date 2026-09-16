rule TTP_XOR_QUAD_CurrentVersionRun_2f9b {
  strings:
    $key_2f9b = { 7c f4 [2] 58 fa [2] 73 d6 [2] 5d f4 [2] 49 ef [2] 46 f5 [2] 58 e8 [2] 5a e9 [2] 41 ef [2] 5d e8 [2] 41 c7 }

  condition:
    any of them
}