rule TTP_XOR_QUAD_CurrentVersionRun_b2c6 {
  strings:
    $key_b2c6 = { e1 a9 [2] c5 a7 [2] ee 8b [2] c0 a9 [2] d4 b2 [2] db a8 [2] c5 b5 [2] c7 b4 [2] dc b2 [2] c0 b5 [2] dc 9a }

  condition:
    any of them
}