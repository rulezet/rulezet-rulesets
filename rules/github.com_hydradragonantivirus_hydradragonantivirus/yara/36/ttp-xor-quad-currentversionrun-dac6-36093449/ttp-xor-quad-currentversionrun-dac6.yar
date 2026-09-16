rule TTP_XOR_QUAD_CurrentVersionRun_dac6 {
  strings:
    $key_dac6 = { 89 a9 [2] ad a7 [2] 86 8b [2] a8 a9 [2] bc b2 [2] b3 a8 [2] ad b5 [2] af b4 [2] b4 b2 [2] a8 b5 [2] b4 9a }

  condition:
    any of them
}