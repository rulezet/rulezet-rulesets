rule TTP_XOR_QUAD_CurrentVersionRun_38b2 {
  strings:
    $key_38b2 = { 6b dd [2] 4f d3 [2] 64 ff [2] 4a dd [2] 5e c6 [2] 51 dc [2] 4f c1 [2] 4d c0 [2] 56 c6 [2] 4a c1 [2] 56 ee }

  condition:
    any of them
}