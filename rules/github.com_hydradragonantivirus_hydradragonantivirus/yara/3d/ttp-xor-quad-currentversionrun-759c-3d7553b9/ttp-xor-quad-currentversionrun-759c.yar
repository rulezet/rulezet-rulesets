rule TTP_XOR_QUAD_CurrentVersionRun_759c {
  strings:
    $key_759c = { 26 f3 [2] 02 fd [2] 29 d1 [2] 07 f3 [2] 13 e8 [2] 1c f2 [2] 02 ef [2] 00 ee [2] 1b e8 [2] 07 ef [2] 1b c0 }

  condition:
    any of them
}