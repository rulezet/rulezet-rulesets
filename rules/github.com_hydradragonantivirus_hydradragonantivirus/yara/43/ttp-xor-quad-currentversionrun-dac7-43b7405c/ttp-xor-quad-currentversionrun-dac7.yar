rule TTP_XOR_QUAD_CurrentVersionRun_dac7 {
  strings:
    $key_dac7 = { 89 a8 [2] ad a6 [2] 86 8a [2] a8 a8 [2] bc b3 [2] b3 a9 [2] ad b4 [2] af b5 [2] b4 b3 [2] a8 b4 [2] b4 9b }

  condition:
    any of them
}