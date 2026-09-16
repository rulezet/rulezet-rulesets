rule TTP_XOR_QUAD_CurrentVersionRun_da4b {
  strings:
    $key_da4b = { 89 24 [2] ad 2a [2] 86 06 [2] a8 24 [2] bc 3f [2] b3 25 [2] ad 38 [2] af 39 [2] b4 3f [2] a8 38 [2] b4 17 }

  condition:
    any of them
}