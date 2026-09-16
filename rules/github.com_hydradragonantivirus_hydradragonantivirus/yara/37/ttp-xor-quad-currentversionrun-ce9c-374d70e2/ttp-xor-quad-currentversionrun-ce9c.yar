rule TTP_XOR_QUAD_CurrentVersionRun_ce9c {
  strings:
    $key_ce9c = { 9d f3 [2] b9 fd [2] 92 d1 [2] bc f3 [2] a8 e8 [2] a7 f2 [2] b9 ef [2] bb ee [2] a0 e8 [2] bc ef [2] a0 c0 }

  condition:
    any of them
}