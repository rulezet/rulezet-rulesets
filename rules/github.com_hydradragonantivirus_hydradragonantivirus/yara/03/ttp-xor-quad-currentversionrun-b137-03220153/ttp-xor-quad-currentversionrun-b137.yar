rule TTP_XOR_QUAD_CurrentVersionRun_b137 {
  strings:
    $key_b137 = { e2 58 [2] c6 56 [2] ed 7a [2] c3 58 [2] d7 43 [2] d8 59 [2] c6 44 [2] c4 45 [2] df 43 [2] c3 44 [2] df 6b }

  condition:
    any of them
}