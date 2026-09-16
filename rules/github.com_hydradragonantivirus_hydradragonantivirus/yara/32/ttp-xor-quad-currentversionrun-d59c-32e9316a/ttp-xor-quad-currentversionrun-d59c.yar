rule TTP_XOR_QUAD_CurrentVersionRun_d59c {
  strings:
    $key_d59c = { 86 f3 [2] a2 fd [2] 89 d1 [2] a7 f3 [2] b3 e8 [2] bc f2 [2] a2 ef [2] a0 ee [2] bb e8 [2] a7 ef [2] bb c0 }

  condition:
    any of them
}