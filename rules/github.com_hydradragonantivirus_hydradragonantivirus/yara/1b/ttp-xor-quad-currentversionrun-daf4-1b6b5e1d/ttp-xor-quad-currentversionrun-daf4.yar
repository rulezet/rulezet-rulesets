rule TTP_XOR_QUAD_CurrentVersionRun_daf4 {
  strings:
    $key_daf4 = { 89 9b [2] ad 95 [2] 86 b9 [2] a8 9b [2] bc 80 [2] b3 9a [2] ad 87 [2] af 86 [2] b4 80 [2] a8 87 [2] b4 a8 }

  condition:
    any of them
}