rule TTP_XOR_QUAD_CurrentVersionRun_c3b2 {
  strings:
    $key_c3b2 = { 90 dd [2] b4 d3 [2] 9f ff [2] b1 dd [2] a5 c6 [2] aa dc [2] b4 c1 [2] b6 c0 [2] ad c6 [2] b1 c1 [2] ad ee }

  condition:
    any of them
}