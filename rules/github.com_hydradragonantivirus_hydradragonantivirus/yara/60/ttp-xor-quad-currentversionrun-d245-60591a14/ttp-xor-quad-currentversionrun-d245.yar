rule TTP_XOR_QUAD_CurrentVersionRun_d245 {
  strings:
    $key_d245 = { 81 2a [2] a5 24 [2] 8e 08 [2] a0 2a [2] b4 31 [2] bb 2b [2] a5 36 [2] a7 37 [2] bc 31 [2] a0 36 [2] bc 19 }

  condition:
    any of them
}