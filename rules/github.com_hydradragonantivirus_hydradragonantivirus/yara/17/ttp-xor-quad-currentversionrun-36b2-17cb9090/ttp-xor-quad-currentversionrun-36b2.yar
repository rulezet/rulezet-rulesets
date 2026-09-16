rule TTP_XOR_QUAD_CurrentVersionRun_36b2 {
  strings:
    $key_36b2 = { 65 dd [2] 41 d3 [2] 6a ff [2] 44 dd [2] 50 c6 [2] 5f dc [2] 41 c1 [2] 43 c0 [2] 58 c6 [2] 44 c1 [2] 58 ee }

  condition:
    any of them
}