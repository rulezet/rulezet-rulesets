rule TTP_XOR_QUAD_CurrentVersionRun_409c {
  strings:
    $key_409c = { 13 f3 [2] 37 fd [2] 1c d1 [2] 32 f3 [2] 26 e8 [2] 29 f2 [2] 37 ef [2] 35 ee [2] 2e e8 [2] 32 ef [2] 2e c0 }

  condition:
    any of them
}