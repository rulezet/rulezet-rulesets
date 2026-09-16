rule TTP_XOR_QUAD_CurrentVersionRun_419b {
  strings:
    $key_419b = { 12 f4 [2] 36 fa [2] 1d d6 [2] 33 f4 [2] 27 ef [2] 28 f5 [2] 36 e8 [2] 34 e9 [2] 2f ef [2] 33 e8 [2] 2f c7 }

  condition:
    any of them
}