rule TTP_XOR_QUAD_CurrentVersionRun_b156 {
  strings:
    $key_b156 = { e2 39 [2] c6 37 [2] ed 1b [2] c3 39 [2] d7 22 [2] d8 38 [2] c6 25 [2] c4 24 [2] df 22 [2] c3 25 [2] df 0a }

  condition:
    any of them
}