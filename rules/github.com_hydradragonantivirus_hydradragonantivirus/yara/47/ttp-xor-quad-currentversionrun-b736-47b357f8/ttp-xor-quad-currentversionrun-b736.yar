rule TTP_XOR_QUAD_CurrentVersionRun_b736 {
  strings:
    $key_b736 = { e4 59 [2] c0 57 [2] eb 7b [2] c5 59 [2] d1 42 [2] de 58 [2] c0 45 [2] c2 44 [2] d9 42 [2] c5 45 [2] d9 6a }

  condition:
    any of them
}