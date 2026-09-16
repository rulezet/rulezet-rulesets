rule TTP_XOR_QUAD_CurrentVersionRun_ca97 {
  strings:
    $key_ca97 = { 99 f8 [2] bd f6 [2] 96 da [2] b8 f8 [2] ac e3 [2] a3 f9 [2] bd e4 [2] bf e5 [2] a4 e3 [2] b8 e4 [2] a4 cb }

  condition:
    any of them
}