rule TTP_XOR_QUAD_CurrentVersionRun_d557 {
  strings:
    $key_d557 = { 86 38 [2] a2 36 [2] 89 1a [2] a7 38 [2] b3 23 [2] bc 39 [2] a2 24 [2] a0 25 [2] bb 23 [2] a7 24 [2] bb 0b }

  condition:
    any of them
}