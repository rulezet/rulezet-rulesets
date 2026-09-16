rule TTP_XOR_QUAD_CurrentVersionRun_18b2 {
  strings:
    $key_18b2 = { 4b dd [2] 6f d3 [2] 44 ff [2] 6a dd [2] 7e c6 [2] 71 dc [2] 6f c1 [2] 6d c0 [2] 76 c6 [2] 6a c1 [2] 76 ee }

  condition:
    any of them
}