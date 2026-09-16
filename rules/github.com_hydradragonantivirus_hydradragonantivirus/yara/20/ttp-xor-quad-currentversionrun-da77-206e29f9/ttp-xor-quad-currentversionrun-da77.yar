rule TTP_XOR_QUAD_CurrentVersionRun_da77 {
  strings:
    $key_da77 = { 89 18 [2] ad 16 [2] 86 3a [2] a8 18 [2] bc 03 [2] b3 19 [2] ad 04 [2] af 05 [2] b4 03 [2] a8 04 [2] b4 2b }

  condition:
    any of them
}