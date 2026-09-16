rule TTP_XOR_QUAD_CurrentVersionRun_709b {
  strings:
    $key_709b = { 23 f4 [2] 07 fa [2] 2c d6 [2] 02 f4 [2] 16 ef [2] 19 f5 [2] 07 e8 [2] 05 e9 [2] 1e ef [2] 02 e8 [2] 1e c7 }

  condition:
    any of them
}