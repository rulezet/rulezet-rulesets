rule TTP_XOR_QUAD_CurrentVersionRun_dac3 {
  strings:
    $key_dac3 = { 89 ac [2] ad a2 [2] 86 8e [2] a8 ac [2] bc b7 [2] b3 ad [2] ad b0 [2] af b1 [2] b4 b7 [2] a8 b0 [2] b4 9f }

  condition:
    any of them
}