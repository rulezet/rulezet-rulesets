rule TTP_XOR_QUAD_CurrentVersionRun_cef9 {
  strings:
    $key_cef9 = { 9d 96 [2] b9 98 [2] 92 b4 [2] bc 96 [2] a8 8d [2] a7 97 [2] b9 8a [2] bb 8b [2] a0 8d [2] bc 8a [2] a0 a5 }

  condition:
    any of them
}