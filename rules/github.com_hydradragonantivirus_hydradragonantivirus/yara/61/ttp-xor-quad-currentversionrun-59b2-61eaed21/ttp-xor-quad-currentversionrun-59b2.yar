rule TTP_XOR_QUAD_CurrentVersionRun_59b2 {
  strings:
    $key_59b2 = { 0a dd [2] 2e d3 [2] 05 ff [2] 2b dd [2] 3f c6 [2] 30 dc [2] 2e c1 [2] 2c c0 [2] 37 c6 [2] 2b c1 [2] 37 ee }

  condition:
    any of them
}