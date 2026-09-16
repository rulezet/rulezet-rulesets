rule TTP_XOR_QUAD_CurrentVersionRun_6bb2 {
  strings:
    $key_6bb2 = { 38 dd [2] 1c d3 [2] 37 ff [2] 19 dd [2] 0d c6 [2] 02 dc [2] 1c c1 [2] 1e c0 [2] 05 c6 [2] 19 c1 [2] 05 ee }

  condition:
    any of them
}