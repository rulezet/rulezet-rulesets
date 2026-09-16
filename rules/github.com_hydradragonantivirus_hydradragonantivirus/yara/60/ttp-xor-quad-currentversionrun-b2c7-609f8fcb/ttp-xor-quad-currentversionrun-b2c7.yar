rule TTP_XOR_QUAD_CurrentVersionRun_b2c7 {
  strings:
    $key_b2c7 = { e1 a8 [2] c5 a6 [2] ee 8a [2] c0 a8 [2] d4 b3 [2] db a9 [2] c5 b4 [2] c7 b5 [2] dc b3 [2] c0 b4 [2] dc 9b }

  condition:
    any of them
}