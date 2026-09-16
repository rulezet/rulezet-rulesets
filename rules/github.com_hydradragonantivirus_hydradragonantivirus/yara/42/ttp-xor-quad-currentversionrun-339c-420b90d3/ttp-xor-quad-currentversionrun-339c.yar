rule TTP_XOR_QUAD_CurrentVersionRun_339c {
  strings:
    $key_339c = { 60 f3 [2] 44 fd [2] 6f d1 [2] 41 f3 [2] 55 e8 [2] 5a f2 [2] 44 ef [2] 46 ee [2] 5d e8 [2] 41 ef [2] 5d c0 }

  condition:
    any of them
}