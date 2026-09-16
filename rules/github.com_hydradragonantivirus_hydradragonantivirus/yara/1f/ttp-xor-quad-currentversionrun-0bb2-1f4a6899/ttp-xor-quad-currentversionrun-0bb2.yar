rule TTP_XOR_QUAD_CurrentVersionRun_0bb2 {
  strings:
    $key_0bb2 = { 58 dd [2] 7c d3 [2] 57 ff [2] 79 dd [2] 6d c6 [2] 62 dc [2] 7c c1 [2] 7e c0 [2] 65 c6 [2] 79 c1 [2] 65 ee }

  condition:
    any of them
}