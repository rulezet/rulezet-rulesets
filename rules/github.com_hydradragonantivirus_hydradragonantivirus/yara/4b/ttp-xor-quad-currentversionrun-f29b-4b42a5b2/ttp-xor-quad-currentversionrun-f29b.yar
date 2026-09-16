rule TTP_XOR_QUAD_CurrentVersionRun_f29b {
  strings:
    $key_f29b = { a1 f4 [2] 85 fa [2] ae d6 [2] 80 f4 [2] 94 ef [2] 9b f5 [2] 85 e8 [2] 87 e9 [2] 9c ef [2] 80 e8 [2] 9c c7 }

  condition:
    any of them
}