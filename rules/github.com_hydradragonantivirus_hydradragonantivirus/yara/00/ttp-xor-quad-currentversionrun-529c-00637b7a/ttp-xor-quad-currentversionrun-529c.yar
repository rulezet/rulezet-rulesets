rule TTP_XOR_QUAD_CurrentVersionRun_529c {
  strings:
    $key_529c = { 01 f3 [2] 25 fd [2] 0e d1 [2] 20 f3 [2] 34 e8 [2] 3b f2 [2] 25 ef [2] 27 ee [2] 3c e8 [2] 20 ef [2] 3c c0 }

  condition:
    any of them
}