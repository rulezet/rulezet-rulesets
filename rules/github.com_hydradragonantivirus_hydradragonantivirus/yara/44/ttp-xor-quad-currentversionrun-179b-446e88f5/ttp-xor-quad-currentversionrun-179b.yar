rule TTP_XOR_QUAD_CurrentVersionRun_179b {
  strings:
    $key_179b = { 44 f4 [2] 60 fa [2] 4b d6 [2] 65 f4 [2] 71 ef [2] 7e f5 [2] 60 e8 [2] 62 e9 [2] 79 ef [2] 65 e8 [2] 79 c7 }

  condition:
    any of them
}