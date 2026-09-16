rule TTP_XOR_QUAD_CurrentVersionRun_ebb2 {
  strings:
    $key_ebb2 = { b8 dd [2] 9c d3 [2] b7 ff [2] 99 dd [2] 8d c6 [2] 82 dc [2] 9c c1 [2] 9e c0 [2] 85 c6 [2] 99 c1 [2] 85 ee }

  condition:
    any of them
}