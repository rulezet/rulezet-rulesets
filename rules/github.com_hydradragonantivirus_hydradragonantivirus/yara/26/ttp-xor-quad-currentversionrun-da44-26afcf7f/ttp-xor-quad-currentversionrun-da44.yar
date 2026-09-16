rule TTP_XOR_QUAD_CurrentVersionRun_da44 {
  strings:
    $key_da44 = { 89 2b [2] ad 25 [2] 86 09 [2] a8 2b [2] bc 30 [2] b3 2a [2] ad 37 [2] af 36 [2] b4 30 [2] a8 37 [2] b4 18 }

  condition:
    any of them
}