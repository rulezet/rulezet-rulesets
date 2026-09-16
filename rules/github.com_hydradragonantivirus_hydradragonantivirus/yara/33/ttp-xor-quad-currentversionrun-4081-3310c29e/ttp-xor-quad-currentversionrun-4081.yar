rule TTP_XOR_QUAD_CurrentVersionRun_4081 {
  strings:
    $key_4081 = { 13 ee [2] 37 e0 [2] 1c cc [2] 32 ee [2] 26 f5 [2] 29 ef [2] 37 f2 [2] 35 f3 [2] 2e f5 [2] 32 f2 [2] 2e dd }

  condition:
    any of them
}