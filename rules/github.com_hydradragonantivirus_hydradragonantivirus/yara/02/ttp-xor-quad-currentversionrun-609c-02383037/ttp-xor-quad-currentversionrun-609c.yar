rule TTP_XOR_QUAD_CurrentVersionRun_609c {
  strings:
    $key_609c = { 33 f3 [2] 17 fd [2] 3c d1 [2] 12 f3 [2] 06 e8 [2] 09 f2 [2] 17 ef [2] 15 ee [2] 0e e8 [2] 12 ef [2] 0e c0 }

  condition:
    any of them
}