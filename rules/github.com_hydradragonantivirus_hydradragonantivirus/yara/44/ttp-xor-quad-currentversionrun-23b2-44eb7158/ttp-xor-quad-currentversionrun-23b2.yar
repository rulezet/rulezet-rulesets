rule TTP_XOR_QUAD_CurrentVersionRun_23b2 {
  strings:
    $key_23b2 = { 70 dd [2] 54 d3 [2] 7f ff [2] 51 dd [2] 45 c6 [2] 4a dc [2] 54 c1 [2] 56 c0 [2] 4d c6 [2] 51 c1 [2] 4d ee }

  condition:
    any of them
}