rule TTP_XOR_QUAD_CurrentVersionRun_d5c9 {
  strings:
    $key_d5c9 = { 86 a6 [2] a2 a8 [2] 89 84 [2] a7 a6 [2] b3 bd [2] bc a7 [2] a2 ba [2] a0 bb [2] bb bd [2] a7 ba [2] bb 95 }

  condition:
    any of them
}