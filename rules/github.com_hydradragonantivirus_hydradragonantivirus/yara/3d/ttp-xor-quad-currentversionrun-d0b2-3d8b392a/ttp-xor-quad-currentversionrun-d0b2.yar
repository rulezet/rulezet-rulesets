rule TTP_XOR_QUAD_CurrentVersionRun_d0b2 {
  strings:
    $key_d0b2 = { 83 dd [2] a7 d3 [2] 8c ff [2] a2 dd [2] b6 c6 [2] b9 dc [2] a7 c1 [2] a5 c0 [2] be c6 [2] a2 c1 [2] be ee }

  condition:
    any of them
}