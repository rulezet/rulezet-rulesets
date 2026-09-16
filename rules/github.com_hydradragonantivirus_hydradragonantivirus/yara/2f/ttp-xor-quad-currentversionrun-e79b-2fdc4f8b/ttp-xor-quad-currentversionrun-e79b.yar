rule TTP_XOR_QUAD_CurrentVersionRun_e79b {
  strings:
    $key_e79b = { b4 f4 [2] 90 fa [2] bb d6 [2] 95 f4 [2] 81 ef [2] 8e f5 [2] 90 e8 [2] 92 e9 [2] 89 ef [2] 95 e8 [2] 89 c7 }

  condition:
    any of them
}