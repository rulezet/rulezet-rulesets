rule TTP_XOR_QUAD_CurrentVersionRun_d597 {
  strings:
    $key_d597 = { 86 f8 [2] a2 f6 [2] 89 da [2] a7 f8 [2] b3 e3 [2] bc f9 [2] a2 e4 [2] a0 e5 [2] bb e3 [2] a7 e4 [2] bb cb }

  condition:
    any of them
}