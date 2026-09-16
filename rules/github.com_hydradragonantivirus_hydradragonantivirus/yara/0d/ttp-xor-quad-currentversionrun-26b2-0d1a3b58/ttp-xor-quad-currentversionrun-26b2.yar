rule TTP_XOR_QUAD_CurrentVersionRun_26b2 {
  strings:
    $key_26b2 = { 75 dd [2] 51 d3 [2] 7a ff [2] 54 dd [2] 40 c6 [2] 4f dc [2] 51 c1 [2] 53 c0 [2] 48 c6 [2] 54 c1 [2] 48 ee }

  condition:
    any of them
}