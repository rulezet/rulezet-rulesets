rule TTP_XOR_QUAD_CurrentVersionRun_d497 {
  strings:
    $key_d497 = { 87 f8 [2] a3 f6 [2] 88 da [2] a6 f8 [2] b2 e3 [2] bd f9 [2] a3 e4 [2] a1 e5 [2] ba e3 [2] a6 e4 [2] ba cb }

  condition:
    any of them
}