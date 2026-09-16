rule TTP_XOR_QUAD_CurrentVersionRun_da6b {
  strings:
    $key_da6b = { 89 04 [2] ad 0a [2] 86 26 [2] a8 04 [2] bc 1f [2] b3 05 [2] ad 18 [2] af 19 [2] b4 1f [2] a8 18 [2] b4 37 }

  condition:
    any of them
}