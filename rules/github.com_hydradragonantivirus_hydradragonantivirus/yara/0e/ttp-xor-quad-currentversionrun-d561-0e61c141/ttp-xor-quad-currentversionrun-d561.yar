rule TTP_XOR_QUAD_CurrentVersionRun_d561 {
  strings:
    $key_d561 = { 86 0e [2] a2 00 [2] 89 2c [2] a7 0e [2] b3 15 [2] bc 0f [2] a2 12 [2] a0 13 [2] bb 15 [2] a7 12 [2] bb 3d }

  condition:
    any of them
}