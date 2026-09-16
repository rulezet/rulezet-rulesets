rule TTP_XOR_QUAD_CurrentVersionRun_c7b2 {
  strings:
    $key_c7b2 = { 94 dd [2] b0 d3 [2] 9b ff [2] b5 dd [2] a1 c6 [2] ae dc [2] b0 c1 [2] b2 c0 [2] a9 c6 [2] b5 c1 [2] a9 ee }

  condition:
    any of them
}