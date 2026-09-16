rule TTP_XOR_QUAD_CurrentVersionRun_c974 {
  strings:
    $key_c974 = { 9a 1b [2] be 15 [2] 95 39 [2] bb 1b [2] af 00 [2] a0 1a [2] be 07 [2] bc 06 [2] a7 00 [2] bb 07 [2] a7 28 }

  condition:
    any of them
}