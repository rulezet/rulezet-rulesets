rule TTP_XOR_QUAD_CurrentVersionRun_d248 {
  strings:
    $key_d248 = { 81 27 [2] a5 29 [2] 8e 05 [2] a0 27 [2] b4 3c [2] bb 26 [2] a5 3b [2] a7 3a [2] bc 3c [2] a0 3b [2] bc 14 }

  condition:
    any of them
}