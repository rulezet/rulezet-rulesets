rule TTP_XOR_QUAD_CurrentVersionRun_e39b {
  strings:
    $key_e39b = { b0 f4 [2] 94 fa [2] bf d6 [2] 91 f4 [2] 85 ef [2] 8a f5 [2] 94 e8 [2] 96 e9 [2] 8d ef [2] 91 e8 [2] 8d c7 }

  condition:
    any of them
}