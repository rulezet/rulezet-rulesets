rule TTP_XOR_QUAD_CurrentVersionRun_039c {
  strings:
    $key_039c = { 50 f3 [2] 74 fd [2] 5f d1 [2] 71 f3 [2] 65 e8 [2] 6a f2 [2] 74 ef [2] 76 ee [2] 6d e8 [2] 71 ef [2] 6d c0 }

  condition:
    any of them
}