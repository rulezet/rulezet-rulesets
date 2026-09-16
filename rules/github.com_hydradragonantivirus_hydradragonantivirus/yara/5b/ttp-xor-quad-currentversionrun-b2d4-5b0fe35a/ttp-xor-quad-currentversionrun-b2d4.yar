rule TTP_XOR_QUAD_CurrentVersionRun_b2d4 {
  strings:
    $key_b2d4 = { e1 bb [2] c5 b5 [2] ee 99 [2] c0 bb [2] d4 a0 [2] db ba [2] c5 a7 [2] c7 a6 [2] dc a0 [2] c0 a7 [2] dc 88 }

  condition:
    any of them
}