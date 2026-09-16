rule TTP_XOR_QUAD_CurrentVersionRun_559c {
  strings:
    $key_559c = { 06 f3 [2] 22 fd [2] 09 d1 [2] 27 f3 [2] 33 e8 [2] 3c f2 [2] 22 ef [2] 20 ee [2] 3b e8 [2] 27 ef [2] 3b c0 }

  condition:
    any of them
}