rule TTP_XOR_QUAD_CurrentVersionRun_019b {
  strings:
    $key_019b = { 52 f4 [2] 76 fa [2] 5d d6 [2] 73 f4 [2] 67 ef [2] 68 f5 [2] 76 e8 [2] 74 e9 [2] 6f ef [2] 73 e8 [2] 6f c7 }

  condition:
    any of them
}