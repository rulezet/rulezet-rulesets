rule TTP_XOR_QUAD_CurrentVersionRun_b2d6 {
  strings:
    $key_b2d6 = { e1 b9 [2] c5 b7 [2] ee 9b [2] c0 b9 [2] d4 a2 [2] db b8 [2] c5 a5 [2] c7 a4 [2] dc a2 [2] c0 a5 [2] dc 8a }

  condition:
    any of them
}