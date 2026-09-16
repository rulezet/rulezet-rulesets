rule TTP_XOR_QUAD_CurrentVersionRun_cf9c {
  strings:
    $key_cf9c = { 9c f3 [2] b8 fd [2] 93 d1 [2] bd f3 [2] a9 e8 [2] a6 f2 [2] b8 ef [2] ba ee [2] a1 e8 [2] bd ef [2] a1 c0 }

  condition:
    any of them
}