rule TTP_XOR_QUAD_CurrentVersionRun_b108 {
  strings:
    $key_b108 = { e2 67 [2] c6 69 [2] ed 45 [2] c3 67 [2] d7 7c [2] d8 66 [2] c6 7b [2] c4 7a [2] df 7c [2] c3 7b [2] df 54 }

  condition:
    any of them
}