rule TTP_XOR_QUAD_CurrentVersionRun_dac9 {
  strings:
    $key_dac9 = { 89 a6 [2] ad a8 [2] 86 84 [2] a8 a6 [2] bc bd [2] b3 a7 [2] ad ba [2] af bb [2] b4 bd [2] a8 ba [2] b4 95 }

  condition:
    any of them
}