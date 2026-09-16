rule TTP_XOR_QUAD_CurrentVersionRun_d269 {
  strings:
    $key_d269 = { 81 06 [2] a5 08 [2] 8e 24 [2] a0 06 [2] b4 1d [2] bb 07 [2] a5 1a [2] a7 1b [2] bc 1d [2] a0 1a [2] bc 35 }

  condition:
    any of them
}