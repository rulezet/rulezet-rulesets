rule TTP_XOR_QUAD_CurrentVersionRun_cbf4 {
  strings:
    $key_cbf4 = { 98 9b [2] bc 95 [2] 97 b9 [2] b9 9b [2] ad 80 [2] a2 9a [2] bc 87 [2] be 86 [2] a5 80 [2] b9 87 [2] a5 a8 }

  condition:
    any of them
}