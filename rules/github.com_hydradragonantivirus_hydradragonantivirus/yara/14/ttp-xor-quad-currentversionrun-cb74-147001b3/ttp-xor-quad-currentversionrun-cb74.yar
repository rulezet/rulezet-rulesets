rule TTP_XOR_QUAD_CurrentVersionRun_cb74 {
  strings:
    $key_cb74 = { 98 1b [2] bc 15 [2] 97 39 [2] b9 1b [2] ad 00 [2] a2 1a [2] bc 07 [2] be 06 [2] a5 00 [2] b9 07 [2] a5 28 }

  condition:
    any of them
}