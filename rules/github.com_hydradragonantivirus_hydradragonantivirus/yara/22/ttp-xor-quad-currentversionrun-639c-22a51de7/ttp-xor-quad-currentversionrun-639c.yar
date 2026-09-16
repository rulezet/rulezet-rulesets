rule TTP_XOR_QUAD_CurrentVersionRun_639c {
  strings:
    $key_639c = { 30 f3 [2] 14 fd [2] 3f d1 [2] 11 f3 [2] 05 e8 [2] 0a f2 [2] 14 ef [2] 16 ee [2] 0d e8 [2] 11 ef [2] 0d c0 }

  condition:
    any of them
}