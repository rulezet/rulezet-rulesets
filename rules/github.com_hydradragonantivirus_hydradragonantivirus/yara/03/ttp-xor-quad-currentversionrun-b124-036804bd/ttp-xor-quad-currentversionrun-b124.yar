rule TTP_XOR_QUAD_CurrentVersionRun_b124 {
  strings:
    $key_b124 = { e2 4b [2] c6 45 [2] ed 69 [2] c3 4b [2] d7 50 [2] d8 4a [2] c6 57 [2] c4 56 [2] df 50 [2] c3 57 [2] df 78 }

  condition:
    any of them
}