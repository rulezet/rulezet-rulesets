rule TTP_XOR_QUAD_CurrentVersionRun_b2d2 {
  strings:
    $key_b2d2 = { e1 bd [2] c5 b3 [2] ee 9f [2] c0 bd [2] d4 a6 [2] db bc [2] c5 a1 [2] c7 a0 [2] dc a6 [2] c0 a1 [2] dc 8e }

  condition:
    any of them
}