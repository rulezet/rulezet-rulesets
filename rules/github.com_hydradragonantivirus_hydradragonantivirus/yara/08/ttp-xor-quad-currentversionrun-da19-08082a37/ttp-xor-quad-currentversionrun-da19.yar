rule TTP_XOR_QUAD_CurrentVersionRun_da19 {
  strings:
    $key_da19 = { 89 76 [2] ad 78 [2] 86 54 [2] a8 76 [2] bc 6d [2] b3 77 [2] ad 6a [2] af 6b [2] b4 6d [2] a8 6a [2] b4 45 }

  condition:
    any of them
}