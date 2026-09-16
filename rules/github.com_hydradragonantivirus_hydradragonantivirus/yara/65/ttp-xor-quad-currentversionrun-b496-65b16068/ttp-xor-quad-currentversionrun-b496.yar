rule TTP_XOR_QUAD_CurrentVersionRun_b496 {
  strings:
    $key_b496 = { e7 f9 [2] c3 f7 [2] e8 db [2] c6 f9 [2] d2 e2 [2] dd f8 [2] c3 e5 [2] c1 e4 [2] da e2 [2] c6 e5 [2] da ca }

  condition:
    any of them
}