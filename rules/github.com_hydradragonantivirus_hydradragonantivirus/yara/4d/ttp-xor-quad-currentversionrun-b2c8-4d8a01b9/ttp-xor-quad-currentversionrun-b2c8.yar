rule TTP_XOR_QUAD_CurrentVersionRun_b2c8 {
  strings:
    $key_b2c8 = { e1 a7 [2] c5 a9 [2] ee 85 [2] c0 a7 [2] d4 bc [2] db a6 [2] c5 bb [2] c7 ba [2] dc bc [2] c0 bb [2] dc 94 }

  condition:
    any of them
}