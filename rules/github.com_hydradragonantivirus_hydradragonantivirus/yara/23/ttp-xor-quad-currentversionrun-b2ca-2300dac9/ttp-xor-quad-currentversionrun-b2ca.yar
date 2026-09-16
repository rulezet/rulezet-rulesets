rule TTP_XOR_QUAD_CurrentVersionRun_b2ca {
  strings:
    $key_b2ca = { e1 a5 [2] c5 ab [2] ee 87 [2] c0 a5 [2] d4 be [2] db a4 [2] c5 b9 [2] c7 b8 [2] dc be [2] c0 b9 [2] dc 96 }

  condition:
    any of them
}