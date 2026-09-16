rule TTP_XOR_QUAD_CurrentVersionRun_cf97 {
  strings:
    $key_cf97 = { 9c f8 [2] b8 f6 [2] 93 da [2] bd f8 [2] a9 e3 [2] a6 f9 [2] b8 e4 [2] ba e5 [2] a1 e3 [2] bd e4 [2] a1 cb }

  condition:
    any of them
}