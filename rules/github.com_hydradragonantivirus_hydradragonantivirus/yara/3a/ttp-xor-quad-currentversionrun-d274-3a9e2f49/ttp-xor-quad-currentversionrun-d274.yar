rule TTP_XOR_QUAD_CurrentVersionRun_d274 {
  strings:
    $key_d274 = { 81 1b [2] a5 15 [2] 8e 39 [2] a0 1b [2] b4 00 [2] bb 1a [2] a5 07 [2] a7 06 [2] bc 00 [2] a0 07 [2] bc 28 }

  condition:
    any of them
}