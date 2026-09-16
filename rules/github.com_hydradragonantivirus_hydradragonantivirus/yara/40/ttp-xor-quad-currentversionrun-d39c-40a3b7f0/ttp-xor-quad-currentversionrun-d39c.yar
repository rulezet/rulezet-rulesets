rule TTP_XOR_QUAD_CurrentVersionRun_d39c {
  strings:
    $key_d39c = { 80 f3 [2] a4 fd [2] 8f d1 [2] a1 f3 [2] b5 e8 [2] ba f2 [2] a4 ef [2] a6 ee [2] bd e8 [2] a1 ef [2] bd c0 }

  condition:
    any of them
}