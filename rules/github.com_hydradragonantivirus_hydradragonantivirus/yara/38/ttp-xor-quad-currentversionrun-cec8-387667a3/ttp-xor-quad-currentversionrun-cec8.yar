rule TTP_XOR_QUAD_CurrentVersionRun_cec8 {
  strings:
    $key_cec8 = { 9d a7 [2] b9 a9 [2] 92 85 [2] bc a7 [2] a8 bc [2] a7 a6 [2] b9 bb [2] bb ba [2] a0 bc [2] bc bb [2] a0 94 }

  condition:
    any of them
}