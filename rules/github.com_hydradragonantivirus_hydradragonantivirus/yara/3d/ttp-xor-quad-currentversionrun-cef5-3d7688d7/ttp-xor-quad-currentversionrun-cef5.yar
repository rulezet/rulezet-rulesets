rule TTP_XOR_QUAD_CurrentVersionRun_cef5 {
  strings:
    $key_cef5 = { 9d 9a [2] b9 94 [2] 92 b8 [2] bc 9a [2] a8 81 [2] a7 9b [2] b9 86 [2] bb 87 [2] a0 81 [2] bc 86 [2] a0 a9 }

  condition:
    any of them
}