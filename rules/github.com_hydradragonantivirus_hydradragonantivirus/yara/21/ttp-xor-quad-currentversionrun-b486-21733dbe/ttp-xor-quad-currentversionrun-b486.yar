rule TTP_XOR_QUAD_CurrentVersionRun_b486 {
  strings:
    $key_b486 = { e7 e9 [2] c3 e7 [2] e8 cb [2] c6 e9 [2] d2 f2 [2] dd e8 [2] c3 f5 [2] c1 f4 [2] da f2 [2] c6 f5 [2] da da }

  condition:
    any of them
}