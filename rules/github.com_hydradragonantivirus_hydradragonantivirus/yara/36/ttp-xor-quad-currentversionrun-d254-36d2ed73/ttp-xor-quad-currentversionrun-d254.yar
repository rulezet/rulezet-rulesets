rule TTP_XOR_QUAD_CurrentVersionRun_d254 {
  strings:
    $key_d254 = { 81 3b [2] a5 35 [2] 8e 19 [2] a0 3b [2] b4 20 [2] bb 3a [2] a5 27 [2] a7 26 [2] bc 20 [2] a0 27 [2] bc 08 }

  condition:
    any of them
}