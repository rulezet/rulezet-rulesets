rule TTP_XOR_QUAD_CurrentVersionRun_58b2 {
  strings:
    $key_58b2 = { 0b dd [2] 2f d3 [2] 04 ff [2] 2a dd [2] 3e c6 [2] 31 dc [2] 2f c1 [2] 2d c0 [2] 36 c6 [2] 2a c1 [2] 36 ee }

  condition:
    any of them
}