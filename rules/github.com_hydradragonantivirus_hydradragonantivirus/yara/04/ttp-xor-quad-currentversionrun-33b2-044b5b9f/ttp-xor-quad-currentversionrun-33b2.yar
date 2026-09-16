rule TTP_XOR_QUAD_CurrentVersionRun_33b2 {
  strings:
    $key_33b2 = { 60 dd [2] 44 d3 [2] 6f ff [2] 41 dd [2] 55 c6 [2] 5a dc [2] 44 c1 [2] 46 c0 [2] 5d c6 [2] 41 c1 [2] 5d ee }

  condition:
    any of them
}