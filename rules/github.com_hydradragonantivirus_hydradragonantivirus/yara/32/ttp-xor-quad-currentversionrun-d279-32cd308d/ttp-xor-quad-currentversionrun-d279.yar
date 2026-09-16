rule TTP_XOR_QUAD_CurrentVersionRun_d279 {
  strings:
    $key_d279 = { 81 16 [2] a5 18 [2] 8e 34 [2] a0 16 [2] b4 0d [2] bb 17 [2] a5 0a [2] a7 0b [2] bc 0d [2] a0 0a [2] bc 25 }

  condition:
    any of them
}