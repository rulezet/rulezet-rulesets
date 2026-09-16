rule TTP_XOR_QUAD_CurrentVersionRun_c9d5 {
  strings:
    $key_c9d5 = { 9a ba [2] be b4 [2] 95 98 [2] bb ba [2] af a1 [2] a0 bb [2] be a6 [2] bc a7 [2] a7 a1 [2] bb a6 [2] a7 89 }

  condition:
    any of them
}