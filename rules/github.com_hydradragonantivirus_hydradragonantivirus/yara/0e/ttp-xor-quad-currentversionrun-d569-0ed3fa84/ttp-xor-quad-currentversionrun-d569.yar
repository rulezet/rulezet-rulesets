rule TTP_XOR_QUAD_CurrentVersionRun_d569 {
  strings:
    $key_d569 = { 86 06 [2] a2 08 [2] 89 24 [2] a7 06 [2] b3 1d [2] bc 07 [2] a2 1a [2] a0 1b [2] bb 1d [2] a7 1a [2] bb 35 }

  condition:
    any of them
}