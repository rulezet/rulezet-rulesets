rule TTP_XOR_QUAD_CurrentVersionRun_d573 {
  strings:
    $key_d573 = { 86 1c [2] a2 12 [2] 89 3e [2] a7 1c [2] b3 07 [2] bc 1d [2] a2 00 [2] a0 01 [2] bb 07 [2] a7 00 [2] bb 2f }

  condition:
    any of them
}