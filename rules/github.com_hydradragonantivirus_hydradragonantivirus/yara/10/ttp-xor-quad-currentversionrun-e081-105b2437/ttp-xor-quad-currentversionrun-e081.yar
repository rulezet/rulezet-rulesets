rule TTP_XOR_QUAD_CurrentVersionRun_e081 {
  strings:
    $key_e081 = { b3 ee [2] 97 e0 [2] bc cc [2] 92 ee [2] 86 f5 [2] 89 ef [2] 97 f2 [2] 95 f3 [2] 8e f5 [2] 92 f2 [2] 8e dd }

  condition:
    any of them
}