rule TTP_XOR_QUAD_CurrentVersionRun_d568 {
  strings:
    $key_d568 = { 86 07 [2] a2 09 [2] 89 25 [2] a7 07 [2] b3 1c [2] bc 06 [2] a2 1b [2] a0 1a [2] bb 1c [2] a7 1b [2] bb 34 }

  condition:
    any of them
}