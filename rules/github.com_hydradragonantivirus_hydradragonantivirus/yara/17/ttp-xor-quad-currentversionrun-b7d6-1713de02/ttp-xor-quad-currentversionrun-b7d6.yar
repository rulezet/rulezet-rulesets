rule TTP_XOR_QUAD_CurrentVersionRun_b7d6 {
  strings:
    $key_b7d6 = { e4 b9 [2] c0 b7 [2] eb 9b [2] c5 b9 [2] d1 a2 [2] de b8 [2] c0 a5 [2] c2 a4 [2] d9 a2 [2] c5 a5 [2] d9 8a }

  condition:
    any of them
}