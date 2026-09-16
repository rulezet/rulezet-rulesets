rule TTP_XOR_QUAD_CurrentVersionRun_53b2 {
  strings:
    $key_53b2 = { 00 dd [2] 24 d3 [2] 0f ff [2] 21 dd [2] 35 c6 [2] 3a dc [2] 24 c1 [2] 26 c0 [2] 3d c6 [2] 21 c1 [2] 3d ee }

  condition:
    any of them
}