rule TTP_XOR_QUAD_CurrentVersionRun_01b2 {
  strings:
    $key_01b2 = { 52 dd [2] 76 d3 [2] 5d ff [2] 73 dd [2] 67 c6 [2] 68 dc [2] 76 c1 [2] 74 c0 [2] 6f c6 [2] 73 c1 [2] 6f ee }

  condition:
    any of them
}