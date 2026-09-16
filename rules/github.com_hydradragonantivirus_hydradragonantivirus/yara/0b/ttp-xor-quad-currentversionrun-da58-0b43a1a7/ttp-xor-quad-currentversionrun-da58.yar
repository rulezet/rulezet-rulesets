rule TTP_XOR_QUAD_CurrentVersionRun_da58 {
  strings:
    $key_da58 = { 89 37 [2] ad 39 [2] 86 15 [2] a8 37 [2] bc 2c [2] b3 36 [2] ad 2b [2] af 2a [2] b4 2c [2] a8 2b [2] b4 04 }

  condition:
    any of them
}