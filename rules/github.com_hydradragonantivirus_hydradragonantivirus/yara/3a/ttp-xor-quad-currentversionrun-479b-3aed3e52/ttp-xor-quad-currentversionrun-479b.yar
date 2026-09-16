rule TTP_XOR_QUAD_CurrentVersionRun_479b {
  strings:
    $key_479b = { 14 f4 [2] 30 fa [2] 1b d6 [2] 35 f4 [2] 21 ef [2] 2e f5 [2] 30 e8 [2] 32 e9 [2] 29 ef [2] 35 e8 [2] 29 c7 }

  condition:
    any of them
}