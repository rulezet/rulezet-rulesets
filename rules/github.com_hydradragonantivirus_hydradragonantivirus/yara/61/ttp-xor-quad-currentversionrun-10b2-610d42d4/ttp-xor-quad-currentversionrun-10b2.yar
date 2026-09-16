rule TTP_XOR_QUAD_CurrentVersionRun_10b2 {
  strings:
    $key_10b2 = { 43 dd [2] 67 d3 [2] 4c ff [2] 62 dd [2] 76 c6 [2] 79 dc [2] 67 c1 [2] 65 c0 [2] 7e c6 [2] 62 c1 [2] 7e ee }

  condition:
    any of them
}