rule TTP_XOR_QUAD_CurrentVersionRun_b2d5 {
  strings:
    $key_b2d5 = { e1 ba [2] c5 b4 [2] ee 98 [2] c0 ba [2] d4 a1 [2] db bb [2] c5 a6 [2] c7 a7 [2] dc a1 [2] c0 a6 [2] dc 89 }

  condition:
    any of them
}