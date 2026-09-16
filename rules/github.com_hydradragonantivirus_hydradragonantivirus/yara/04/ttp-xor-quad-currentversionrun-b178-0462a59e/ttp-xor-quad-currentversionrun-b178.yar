rule TTP_XOR_QUAD_CurrentVersionRun_b178 {
  strings:
    $key_b178 = { e2 17 [2] c6 19 [2] ed 35 [2] c3 17 [2] d7 0c [2] d8 16 [2] c6 0b [2] c4 0a [2] df 0c [2] c3 0b [2] df 24 }

  condition:
    any of them
}