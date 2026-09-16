rule TTP_XOR_QUAD_CurrentVersionRun_139c {
  strings:
    $key_139c = { 40 f3 [2] 64 fd [2] 4f d1 [2] 61 f3 [2] 75 e8 [2] 7a f2 [2] 64 ef [2] 66 ee [2] 7d e8 [2] 61 ef [2] 7d c0 }

  condition:
    any of them
}