rule TTP_XOR_QUAD_CurrentVersionRun_46b2 {
  strings:
    $key_46b2 = { 15 dd [2] 31 d3 [2] 1a ff [2] 34 dd [2] 20 c6 [2] 2f dc [2] 31 c1 [2] 33 c0 [2] 28 c6 [2] 34 c1 [2] 28 ee }

  condition:
    any of them
}