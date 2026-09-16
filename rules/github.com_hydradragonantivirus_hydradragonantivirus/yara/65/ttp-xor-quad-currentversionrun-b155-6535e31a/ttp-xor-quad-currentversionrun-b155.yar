rule TTP_XOR_QUAD_CurrentVersionRun_b155 {
  strings:
    $key_b155 = { e2 3a [2] c6 34 [2] ed 18 [2] c3 3a [2] d7 21 [2] d8 3b [2] c6 26 [2] c4 27 [2] df 21 [2] c3 26 [2] df 09 }

  condition:
    any of them
}