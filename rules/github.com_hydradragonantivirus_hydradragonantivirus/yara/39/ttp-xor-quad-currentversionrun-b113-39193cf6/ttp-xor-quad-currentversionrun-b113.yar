rule TTP_XOR_QUAD_CurrentVersionRun_b113 {
  strings:
    $key_b113 = { e2 7c [2] c6 72 [2] ed 5e [2] c3 7c [2] d7 67 [2] d8 7d [2] c6 60 [2] c4 61 [2] df 67 [2] c3 60 [2] df 4f }

  condition:
    any of them
}