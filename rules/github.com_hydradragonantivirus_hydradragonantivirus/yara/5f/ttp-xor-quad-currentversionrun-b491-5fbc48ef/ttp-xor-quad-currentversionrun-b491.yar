rule TTP_XOR_QUAD_CurrentVersionRun_b491 {
  strings:
    $key_b491 = { e7 fe [2] c3 f0 [2] e8 dc [2] c6 fe [2] d2 e5 [2] dd ff [2] c3 e2 [2] c1 e3 [2] da e5 [2] c6 e2 [2] da cd }

  condition:
    any of them
}