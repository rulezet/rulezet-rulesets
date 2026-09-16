rule TTP_XOR_QUAD_CurrentVersionRun_c9e8 {
  strings:
    $key_c9e8 = { 9a 87 [2] be 89 [2] 95 a5 [2] bb 87 [2] af 9c [2] a0 86 [2] be 9b [2] bc 9a [2] a7 9c [2] bb 9b [2] a7 b4 }

  condition:
    any of them
}