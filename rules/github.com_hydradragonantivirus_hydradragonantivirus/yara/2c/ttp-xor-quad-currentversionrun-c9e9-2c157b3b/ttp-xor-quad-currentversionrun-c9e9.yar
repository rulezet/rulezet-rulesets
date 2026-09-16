rule TTP_XOR_QUAD_CurrentVersionRun_c9e9 {
  strings:
    $key_c9e9 = { 9a 86 [2] be 88 [2] 95 a4 [2] bb 86 [2] af 9d [2] a0 87 [2] be 9a [2] bc 9b [2] a7 9d [2] bb 9a [2] a7 b5 }

  condition:
    any of them
}