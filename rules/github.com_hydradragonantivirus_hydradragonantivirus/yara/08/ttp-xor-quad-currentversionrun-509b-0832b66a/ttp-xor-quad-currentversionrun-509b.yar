rule TTP_XOR_QUAD_CurrentVersionRun_509b {
  strings:
    $key_509b = { 03 f4 [2] 27 fa [2] 0c d6 [2] 22 f4 [2] 36 ef [2] 39 f5 [2] 27 e8 [2] 25 e9 [2] 3e ef [2] 22 e8 [2] 3e c7 }

  condition:
    any of them
}