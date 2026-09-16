rule TTP_XOR_QUAD_CurrentVersionRun_d2f5 {
  strings:
    $key_d2f5 = { 81 9a [2] a5 94 [2] 8e b8 [2] a0 9a [2] b4 81 [2] bb 9b [2] a5 86 [2] a7 87 [2] bc 81 [2] a0 86 [2] bc a9 }

  condition:
    any of them
}