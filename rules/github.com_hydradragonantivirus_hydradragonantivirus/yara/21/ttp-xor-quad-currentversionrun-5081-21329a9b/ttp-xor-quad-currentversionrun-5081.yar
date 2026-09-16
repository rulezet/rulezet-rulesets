rule TTP_XOR_QUAD_CurrentVersionRun_5081 {
  strings:
    $key_5081 = { 03 ee [2] 27 e0 [2] 0c cc [2] 22 ee [2] 36 f5 [2] 39 ef [2] 27 f2 [2] 25 f3 [2] 3e f5 [2] 22 f2 [2] 3e dd }

  condition:
    any of them
}