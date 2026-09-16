rule TTP_XOR_QUAD_CurrentVersionRun_2a9b {
  strings:
    $key_2a9b = { 79 f4 [2] 5d fa [2] 76 d6 [2] 58 f4 [2] 4c ef [2] 43 f5 [2] 5d e8 [2] 5f e9 [2] 44 ef [2] 58 e8 [2] 44 c7 }

  condition:
    any of them
}