rule TTP_XOR_QUAD_CurrentVersionRun_b147 {
  strings:
    $key_b147 = { e2 28 [2] c6 26 [2] ed 0a [2] c3 28 [2] d7 33 [2] d8 29 [2] c6 34 [2] c4 35 [2] df 33 [2] c3 34 [2] df 1b }

  condition:
    any of them
}