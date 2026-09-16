rule TTP_XOR_QUAD_CurrentVersionRun_b6f5 {
  strings:
    $key_b6f5 = { e5 9a [2] c1 94 [2] ea b8 [2] c4 9a [2] d0 81 [2] df 9b [2] c1 86 [2] c3 87 [2] d8 81 [2] c4 86 [2] d8 a9 }

  condition:
    any of them
}