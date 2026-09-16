rule TTP_XOR_QUAD_CurrentVersionRun_c0b2 {
  strings:
    $key_c0b2 = { 93 dd [2] b7 d3 [2] 9c ff [2] b2 dd [2] a6 c6 [2] a9 dc [2] b7 c1 [2] b5 c0 [2] ae c6 [2] b2 c1 [2] ae ee }

  condition:
    any of them
}