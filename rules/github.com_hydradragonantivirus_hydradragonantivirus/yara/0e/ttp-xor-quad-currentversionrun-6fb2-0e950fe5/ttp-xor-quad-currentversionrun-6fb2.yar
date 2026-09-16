rule TTP_XOR_QUAD_CurrentVersionRun_6fb2 {
  strings:
    $key_6fb2 = { 3c dd [2] 18 d3 [2] 33 ff [2] 1d dd [2] 09 c6 [2] 06 dc [2] 18 c1 [2] 1a c0 [2] 01 c6 [2] 1d c1 [2] 01 ee }

  condition:
    any of them
}