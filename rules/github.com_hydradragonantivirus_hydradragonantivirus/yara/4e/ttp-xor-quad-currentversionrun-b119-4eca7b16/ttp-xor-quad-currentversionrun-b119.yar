rule TTP_XOR_QUAD_CurrentVersionRun_b119 {
  strings:
    $key_b119 = { e2 76 [2] c6 78 [2] ed 54 [2] c3 76 [2] d7 6d [2] d8 77 [2] c6 6a [2] c4 6b [2] df 6d [2] c3 6a [2] df 45 }

  condition:
    any of them
}