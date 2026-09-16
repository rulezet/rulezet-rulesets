rule TTP_XOR_QUAD_CurrentVersionRun_6081 {
  strings:
    $key_6081 = { 33 ee [2] 17 e0 [2] 3c cc [2] 12 ee [2] 06 f5 [2] 09 ef [2] 17 f2 [2] 15 f3 [2] 0e f5 [2] 12 f2 [2] 0e dd }

  condition:
    any of them
}