rule TTP_XOR_QUAD_CurrentVersionRun_b1f5 {
  strings:
    $key_b1f5 = { e2 9a [2] c6 94 [2] ed b8 [2] c3 9a [2] d7 81 [2] d8 9b [2] c6 86 [2] c4 87 [2] df 81 [2] c3 86 [2] df a9 }

  condition:
    any of them
}