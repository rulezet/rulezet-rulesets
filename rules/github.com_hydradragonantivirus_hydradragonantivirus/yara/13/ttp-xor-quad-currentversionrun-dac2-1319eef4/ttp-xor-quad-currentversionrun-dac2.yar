rule TTP_XOR_QUAD_CurrentVersionRun_dac2 {
  strings:
    $key_dac2 = { 89 ad [2] ad a3 [2] 86 8f [2] a8 ad [2] bc b6 [2] b3 ac [2] ad b1 [2] af b0 [2] b4 b6 [2] a8 b1 [2] b4 9e }

  condition:
    any of them
}