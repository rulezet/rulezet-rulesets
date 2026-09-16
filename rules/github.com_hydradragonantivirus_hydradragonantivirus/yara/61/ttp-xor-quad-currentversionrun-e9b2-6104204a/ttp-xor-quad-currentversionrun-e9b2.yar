rule TTP_XOR_QUAD_CurrentVersionRun_e9b2 {
  strings:
    $key_e9b2 = { ba dd [2] 9e d3 [2] b5 ff [2] 9b dd [2] 8f c6 [2] 80 dc [2] 9e c1 [2] 9c c0 [2] 87 c6 [2] 9b c1 [2] 87 ee }

  condition:
    any of them
}