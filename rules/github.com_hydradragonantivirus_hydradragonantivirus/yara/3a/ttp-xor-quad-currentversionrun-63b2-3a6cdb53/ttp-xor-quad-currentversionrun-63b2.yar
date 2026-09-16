rule TTP_XOR_QUAD_CurrentVersionRun_63b2 {
  strings:
    $key_63b2 = { 30 dd [2] 14 d3 [2] 3f ff [2] 11 dd [2] 05 c6 [2] 0a dc [2] 14 c1 [2] 16 c0 [2] 0d c6 [2] 11 c1 [2] 0d ee }

  condition:
    any of them
}