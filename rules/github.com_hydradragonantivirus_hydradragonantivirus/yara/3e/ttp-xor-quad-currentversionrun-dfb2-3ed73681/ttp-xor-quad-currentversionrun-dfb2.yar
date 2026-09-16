rule TTP_XOR_QUAD_CurrentVersionRun_dfb2 {
  strings:
    $key_dfb2 = { 8c dd [2] a8 d3 [2] 83 ff [2] ad dd [2] b9 c6 [2] b6 dc [2] a8 c1 [2] aa c0 [2] b1 c6 [2] ad c1 [2] b1 ee }

  condition:
    any of them
}