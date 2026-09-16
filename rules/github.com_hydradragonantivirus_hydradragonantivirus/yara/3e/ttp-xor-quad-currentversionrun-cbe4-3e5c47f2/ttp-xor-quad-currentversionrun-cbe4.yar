rule TTP_XOR_QUAD_CurrentVersionRun_cbe4 {
  strings:
    $key_cbe4 = { 98 8b [2] bc 85 [2] 97 a9 [2] b9 8b [2] ad 90 [2] a2 8a [2] bc 97 [2] be 96 [2] a5 90 [2] b9 97 [2] a5 b8 }

  condition:
    any of them
}