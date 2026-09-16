rule TTP_XOR_QUAD_CurrentVersionRun_78b2 {
  strings:
    $key_78b2 = { 2b dd [2] 0f d3 [2] 24 ff [2] 0a dd [2] 1e c6 [2] 11 dc [2] 0f c1 [2] 0d c0 [2] 16 c6 [2] 0a c1 [2] 16 ee }

  condition:
    any of them
}