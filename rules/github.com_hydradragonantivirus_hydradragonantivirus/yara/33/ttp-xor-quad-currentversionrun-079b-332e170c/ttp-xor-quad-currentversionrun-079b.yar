rule TTP_XOR_QUAD_CurrentVersionRun_079b {
  strings:
    $key_079b = { 54 f4 [2] 70 fa [2] 5b d6 [2] 75 f4 [2] 61 ef [2] 6e f5 [2] 70 e8 [2] 72 e9 [2] 69 ef [2] 75 e8 [2] 69 c7 }

  condition:
    any of them
}