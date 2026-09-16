rule TTP_XOR_QUAD_CurrentVersionRun_b2c9 {
  strings:
    $key_b2c9 = { e1 a6 [2] c5 a8 [2] ee 84 [2] c0 a6 [2] d4 bd [2] db a7 [2] c5 ba [2] c7 bb [2] dc bd [2] c0 ba [2] dc 95 }

  condition:
    any of them
}