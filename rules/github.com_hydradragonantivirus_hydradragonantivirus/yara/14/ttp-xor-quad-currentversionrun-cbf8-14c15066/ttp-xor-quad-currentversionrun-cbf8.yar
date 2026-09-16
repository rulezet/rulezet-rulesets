rule TTP_XOR_QUAD_CurrentVersionRun_cbf8 {
  strings:
    $key_cbf8 = { 98 97 [2] bc 99 [2] 97 b5 [2] b9 97 [2] ad 8c [2] a2 96 [2] bc 8b [2] be 8a [2] a5 8c [2] b9 8b [2] a5 a4 }

  condition:
    any of them
}