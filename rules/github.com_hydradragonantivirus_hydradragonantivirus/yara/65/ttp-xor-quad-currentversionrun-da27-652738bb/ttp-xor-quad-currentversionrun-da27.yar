rule TTP_XOR_QUAD_CurrentVersionRun_da27 {
  strings:
    $key_da27 = { 89 48 [2] ad 46 [2] 86 6a [2] a8 48 [2] bc 53 [2] b3 49 [2] ad 54 [2] af 55 [2] b4 53 [2] a8 54 [2] b4 7b }

  condition:
    any of them
}