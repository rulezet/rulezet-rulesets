rule TTP_XOR_QUAD_CurrentVersionRun_da55 {
  strings:
    $key_da55 = { 89 3a [2] ad 34 [2] 86 18 [2] a8 3a [2] bc 21 [2] b3 3b [2] ad 26 [2] af 27 [2] b4 21 [2] a8 26 [2] b4 09 }

  condition:
    any of them
}