rule TTP_XOR_QUAD_CurrentVersionRun_c29c {
  strings:
    $key_c29c = { 91 f3 [2] b5 fd [2] 9e d1 [2] b0 f3 [2] a4 e8 [2] ab f2 [2] b5 ef [2] b7 ee [2] ac e8 [2] b0 ef [2] ac c0 }

  condition:
    any of them
}