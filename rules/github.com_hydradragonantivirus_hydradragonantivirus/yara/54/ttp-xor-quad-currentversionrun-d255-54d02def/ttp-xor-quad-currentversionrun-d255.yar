rule TTP_XOR_QUAD_CurrentVersionRun_d255 {
  strings:
    $key_d255 = { 81 3a [2] a5 34 [2] 8e 18 [2] a0 3a [2] b4 21 [2] bb 3b [2] a5 26 [2] a7 27 [2] bc 21 [2] a0 26 [2] bc 09 }

  condition:
    any of them
}