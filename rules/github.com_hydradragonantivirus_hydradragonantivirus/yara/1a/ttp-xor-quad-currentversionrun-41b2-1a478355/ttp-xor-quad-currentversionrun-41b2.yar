rule TTP_XOR_QUAD_CurrentVersionRun_41b2 {
  strings:
    $key_41b2 = { 12 dd [2] 36 d3 [2] 1d ff [2] 33 dd [2] 27 c6 [2] 28 dc [2] 36 c1 [2] 34 c0 [2] 2f c6 [2] 33 c1 [2] 2f ee }

  condition:
    any of them
}