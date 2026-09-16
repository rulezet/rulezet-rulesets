rule TTP_XOR_QUAD_CurrentVersionRun_d2f8 {
  strings:
    $key_d2f8 = { 81 97 [2] a5 99 [2] 8e b5 [2] a0 97 [2] b4 8c [2] bb 96 [2] a5 8b [2] a7 8a [2] bc 8c [2] a0 8b [2] bc a4 }

  condition:
    any of them
}