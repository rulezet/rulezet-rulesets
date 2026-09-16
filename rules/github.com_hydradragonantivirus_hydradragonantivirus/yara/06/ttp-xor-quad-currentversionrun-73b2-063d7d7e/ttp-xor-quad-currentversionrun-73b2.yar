rule TTP_XOR_QUAD_CurrentVersionRun_73b2 {
  strings:
    $key_73b2 = { 20 dd [2] 04 d3 [2] 2f ff [2] 01 dd [2] 15 c6 [2] 1a dc [2] 04 c1 [2] 06 c0 [2] 1d c6 [2] 01 c1 [2] 1d ee }

  condition:
    any of them
}