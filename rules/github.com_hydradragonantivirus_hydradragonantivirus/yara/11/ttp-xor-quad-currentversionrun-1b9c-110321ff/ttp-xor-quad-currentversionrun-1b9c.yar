rule TTP_XOR_QUAD_CurrentVersionRun_1b9c {
  strings:
    $key_1b9c = { 48 f3 [2] 6c fd [2] 47 d1 [2] 69 f3 [2] 7d e8 [2] 72 f2 [2] 6c ef [2] 6e ee [2] 75 e8 [2] 69 ef [2] 75 c0 }

  condition:
    any of them
}