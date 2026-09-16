rule TTP_XOR_QUAD_CurrentVersionRun_d2d4 {
  strings:
    $key_d2d4 = { 81 bb [2] a5 b5 [2] 8e 99 [2] a0 bb [2] b4 a0 [2] bb ba [2] a5 a7 [2] a7 a6 [2] bc a0 [2] a0 a7 [2] bc 88 }

  condition:
    any of them
}