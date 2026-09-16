rule TTP_XOR_QUAD_CurrentVersionRun_dac8 {
  strings:
    $key_dac8 = { 89 a7 [2] ad a9 [2] 86 85 [2] a8 a7 [2] bc bc [2] b3 a6 [2] ad bb [2] af ba [2] b4 bc [2] a8 bb [2] b4 94 }

  condition:
    any of them
}