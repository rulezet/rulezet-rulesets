rule TTP_XOR_QUAD_CurrentVersionRun_cef8 {
  strings:
    $key_cef8 = { 9d 97 [2] b9 99 [2] 92 b5 [2] bc 97 [2] a8 8c [2] a7 96 [2] b9 8b [2] bb 8a [2] a0 8c [2] bc 8b [2] a0 a4 }

  condition:
    any of them
}