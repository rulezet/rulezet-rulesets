rule TTP_XOR_QUAD_CurrentVersionRun_d577 {
  strings:
    $key_d577 = { 86 18 [2] a2 16 [2] 89 3a [2] a7 18 [2] b3 03 [2] bc 19 [2] a2 04 [2] a0 05 [2] bb 03 [2] a7 04 [2] bb 2b }

  condition:
    any of them
}