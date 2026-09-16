rule TTP_XOR_QUAD_CurrentVersionRun_da73 {
  strings:
    $key_da73 = { 89 1c [2] ad 12 [2] 86 3e [2] a8 1c [2] bc 07 [2] b3 1d [2] ad 00 [2] af 01 [2] b4 07 [2] a8 00 [2] b4 2f }

  condition:
    any of them
}