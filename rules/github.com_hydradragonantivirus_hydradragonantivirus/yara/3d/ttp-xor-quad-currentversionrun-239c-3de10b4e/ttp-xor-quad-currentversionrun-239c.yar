rule TTP_XOR_QUAD_CurrentVersionRun_239c {
  strings:
    $key_239c = { 70 f3 [2] 54 fd [2] 7f d1 [2] 51 f3 [2] 45 e8 [2] 4a f2 [2] 54 ef [2] 56 ee [2] 4d e8 [2] 51 ef [2] 4d c0 }

  condition:
    any of them
}