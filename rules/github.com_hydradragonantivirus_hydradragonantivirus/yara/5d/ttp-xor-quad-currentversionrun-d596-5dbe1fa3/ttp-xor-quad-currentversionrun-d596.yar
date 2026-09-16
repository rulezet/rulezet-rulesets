rule TTP_XOR_QUAD_CurrentVersionRun_d596 {
  strings:
    $key_d596 = { 86 f9 [2] a2 f7 [2] 89 db [2] a7 f9 [2] b3 e2 [2] bc f8 [2] a2 e5 [2] a0 e4 [2] bb e2 [2] a7 e5 [2] bb ca }

  condition:
    any of them
}