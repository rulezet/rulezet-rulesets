rule TTP_XOR_QUAD_CurrentVersionRun_60b2 {
  strings:
    $key_60b2 = { 33 dd [2] 17 d3 [2] 3c ff [2] 12 dd [2] 06 c6 [2] 09 dc [2] 17 c1 [2] 15 c0 [2] 0e c6 [2] 12 c1 [2] 0e ee }

  condition:
    any of them
}