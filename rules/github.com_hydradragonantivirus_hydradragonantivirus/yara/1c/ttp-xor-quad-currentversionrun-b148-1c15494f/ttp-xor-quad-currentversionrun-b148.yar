rule TTP_XOR_QUAD_CurrentVersionRun_b148 {
  strings:
    $key_b148 = { e2 27 [2] c6 29 [2] ed 05 [2] c3 27 [2] d7 3c [2] d8 26 [2] c6 3b [2] c4 3a [2] df 3c [2] c3 3b [2] df 14 }

  condition:
    any of them
}