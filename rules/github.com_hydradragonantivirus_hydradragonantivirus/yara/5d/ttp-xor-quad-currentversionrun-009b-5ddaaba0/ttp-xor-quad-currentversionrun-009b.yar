rule TTP_XOR_QUAD_CurrentVersionRun_009b {
  strings:
    $key_009b = { 53 f4 [2] 77 fa [2] 5c d6 [2] 72 f4 [2] 66 ef [2] 69 f5 [2] 77 e8 [2] 75 e9 [2] 6e ef [2] 72 e8 [2] 6e c7 }

  condition:
    any of them
}