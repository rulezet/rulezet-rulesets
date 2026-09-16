rule TTP_XOR_QUAD_CurrentVersionRun_d5c8 {
  strings:
    $key_d5c8 = { 86 a7 [2] a2 a9 [2] 89 85 [2] a7 a7 [2] b3 bc [2] bc a6 [2] a2 bb [2] a0 ba [2] bb bc [2] a7 bb [2] bb 94 }

  condition:
    any of them
}