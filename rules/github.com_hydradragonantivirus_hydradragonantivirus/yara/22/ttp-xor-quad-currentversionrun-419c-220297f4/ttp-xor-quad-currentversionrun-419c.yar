rule TTP_XOR_QUAD_CurrentVersionRun_419c {
  strings:
    $key_419c = { 12 f3 [2] 36 fd [2] 1d d1 [2] 33 f3 [2] 27 e8 [2] 28 f2 [2] 36 ef [2] 34 ee [2] 2f e8 [2] 33 ef [2] 2f c0 }

  condition:
    any of them
}