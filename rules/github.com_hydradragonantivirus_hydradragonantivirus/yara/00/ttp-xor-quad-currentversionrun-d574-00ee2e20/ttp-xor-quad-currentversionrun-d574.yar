rule TTP_XOR_QUAD_CurrentVersionRun_d574 {
  strings:
    $key_d574 = { 86 1b [2] a2 15 [2] 89 39 [2] a7 1b [2] b3 00 [2] bc 1a [2] a2 07 [2] a0 06 [2] bb 00 [2] a7 07 [2] bb 28 }

  condition:
    any of them
}