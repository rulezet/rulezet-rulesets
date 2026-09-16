rule TTP_XOR_QUAD_CurrentVersionRun_b487 {
  strings:
    $key_b487 = { e7 e8 [2] c3 e6 [2] e8 ca [2] c6 e8 [2] d2 f3 [2] dd e9 [2] c3 f4 [2] c1 f5 [2] da f3 [2] c6 f4 [2] da db }

  condition:
    any of them
}