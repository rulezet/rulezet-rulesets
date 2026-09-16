rule TTP_XOR_QUAD_CurrentVersionRun_429b {
  strings:
    $key_429b = { 11 f4 [2] 35 fa [2] 1e d6 [2] 30 f4 [2] 24 ef [2] 2b f5 [2] 35 e8 [2] 37 e9 [2] 2c ef [2] 30 e8 [2] 2c c7 }

  condition:
    any of them
}