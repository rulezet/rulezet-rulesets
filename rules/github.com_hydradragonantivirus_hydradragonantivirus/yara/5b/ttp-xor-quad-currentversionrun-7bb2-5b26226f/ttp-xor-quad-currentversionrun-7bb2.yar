rule TTP_XOR_QUAD_CurrentVersionRun_7bb2 {
  strings:
    $key_7bb2 = { 28 dd [2] 0c d3 [2] 27 ff [2] 09 dd [2] 1d c6 [2] 12 dc [2] 0c c1 [2] 0e c0 [2] 15 c6 [2] 09 c1 [2] 15 ee }

  condition:
    any of them
}