rule TTP_XOR_QUAD_CurrentVersionRun_cef4 {
  strings:
    $key_cef4 = { 9d 9b [2] b9 95 [2] 92 b9 [2] bc 9b [2] a8 80 [2] a7 9a [2] b9 87 [2] bb 86 [2] a0 80 [2] bc 87 [2] a0 a8 }

  condition:
    any of them
}