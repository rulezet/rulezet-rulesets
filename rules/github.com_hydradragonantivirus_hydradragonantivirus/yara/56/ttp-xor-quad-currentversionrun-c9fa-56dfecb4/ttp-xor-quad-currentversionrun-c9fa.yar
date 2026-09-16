rule TTP_XOR_QUAD_CurrentVersionRun_c9fa {
  strings:
    $key_c9fa = { 9a 95 [2] be 9b [2] 95 b7 [2] bb 95 [2] af 8e [2] a0 94 [2] be 89 [2] bc 88 [2] a7 8e [2] bb 89 [2] a7 a6 }

  condition:
    any of them
}