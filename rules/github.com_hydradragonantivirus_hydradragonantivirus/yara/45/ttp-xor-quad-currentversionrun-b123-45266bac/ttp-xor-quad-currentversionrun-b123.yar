rule TTP_XOR_QUAD_CurrentVersionRun_b123 {
  strings:
    $key_b123 = { e2 4c [2] c6 42 [2] ed 6e [2] c3 4c [2] d7 57 [2] d8 4d [2] c6 50 [2] c4 51 [2] df 57 [2] c3 50 [2] df 7f }

  condition:
    any of them
}