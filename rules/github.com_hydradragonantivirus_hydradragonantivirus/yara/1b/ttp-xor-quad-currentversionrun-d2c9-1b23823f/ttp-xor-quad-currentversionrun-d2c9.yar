rule TTP_XOR_QUAD_CurrentVersionRun_d2c9 {
  strings:
    $key_d2c9 = { 81 a6 [2] a5 a8 [2] 8e 84 [2] a0 a6 [2] b4 bd [2] bb a7 [2] a5 ba [2] a7 bb [2] bc bd [2] a0 ba [2] bc 95 }

  condition:
    any of them
}