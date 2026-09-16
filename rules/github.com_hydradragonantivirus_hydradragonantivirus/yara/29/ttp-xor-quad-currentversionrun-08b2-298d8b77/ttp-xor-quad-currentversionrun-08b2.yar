rule TTP_XOR_QUAD_CurrentVersionRun_08b2 {
  strings:
    $key_08b2 = { 5b dd [2] 7f d3 [2] 54 ff [2] 7a dd [2] 6e c6 [2] 61 dc [2] 7f c1 [2] 7d c0 [2] 66 c6 [2] 7a c1 [2] 66 ee }

  condition:
    any of them
}