rule TTP_XOR_QUAD_CurrentVersionRun_da54 {
  strings:
    $key_da54 = { 89 3b [2] ad 35 [2] 86 19 [2] a8 3b [2] bc 20 [2] b3 3a [2] ad 27 [2] af 26 [2] b4 20 [2] a8 27 [2] b4 08 }

  condition:
    any of them
}