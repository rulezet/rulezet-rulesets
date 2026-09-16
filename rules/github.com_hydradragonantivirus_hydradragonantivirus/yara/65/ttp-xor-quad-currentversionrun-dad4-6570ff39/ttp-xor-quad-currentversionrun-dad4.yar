rule TTP_XOR_QUAD_CurrentVersionRun_dad4 {
  strings:
    $key_dad4 = { 89 bb [2] ad b5 [2] 86 99 [2] a8 bb [2] bc a0 [2] b3 ba [2] ad a7 [2] af a6 [2] b4 a0 [2] a8 a7 [2] b4 88 }

  condition:
    any of them
}