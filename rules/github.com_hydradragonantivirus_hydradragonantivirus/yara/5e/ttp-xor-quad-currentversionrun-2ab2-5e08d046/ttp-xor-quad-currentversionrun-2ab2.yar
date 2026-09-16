rule TTP_XOR_QUAD_CurrentVersionRun_2ab2 {
  strings:
    $key_2ab2 = { 79 dd [2] 5d d3 [2] 76 ff [2] 58 dd [2] 4c c6 [2] 43 dc [2] 5d c1 [2] 5f c0 [2] 44 c6 [2] 58 c1 [2] 44 ee }

  condition:
    any of them
}