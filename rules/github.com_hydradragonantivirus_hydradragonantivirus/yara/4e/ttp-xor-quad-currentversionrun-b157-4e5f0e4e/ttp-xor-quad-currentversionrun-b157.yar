rule TTP_XOR_QUAD_CurrentVersionRun_b157 {
  strings:
    $key_b157 = { e2 38 [2] c6 36 [2] ed 1a [2] c3 38 [2] d7 23 [2] d8 39 [2] c6 24 [2] c4 25 [2] df 23 [2] c3 24 [2] df 0b }

  condition:
    any of them
}