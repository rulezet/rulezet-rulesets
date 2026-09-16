rule TTP_XOR_QUAD_CurrentVersionRun_d8b2 {
  strings:
    $key_d8b2 = { 8b dd [2] af d3 [2] 84 ff [2] aa dd [2] be c6 [2] b1 dc [2] af c1 [2] ad c0 [2] b6 c6 [2] aa c1 [2] b6 ee }

  condition:
    any of them
}