rule TTP_XOR_QUAD_CurrentVersionRun_729b {
  strings:
    $key_729b = { 21 f4 [2] 05 fa [2] 2e d6 [2] 00 f4 [2] 14 ef [2] 1b f5 [2] 05 e8 [2] 07 e9 [2] 1c ef [2] 00 e8 [2] 1c c7 }

  condition:
    any of them
}