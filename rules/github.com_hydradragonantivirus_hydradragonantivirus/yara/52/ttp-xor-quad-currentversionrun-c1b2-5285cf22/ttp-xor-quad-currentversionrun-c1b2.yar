rule TTP_XOR_QUAD_CurrentVersionRun_c1b2 {
  strings:
    $key_c1b2 = { 92 dd [2] b6 d3 [2] 9d ff [2] b3 dd [2] a7 c6 [2] a8 dc [2] b6 c1 [2] b4 c0 [2] af c6 [2] b3 c1 [2] af ee }

  condition:
    any of them
}