rule TTP_XOR_QUAD_CurrentVersionRun_b7d5 {
  strings:
    $key_b7d5 = { e4 ba [2] c0 b4 [2] eb 98 [2] c5 ba [2] d1 a1 [2] de bb [2] c0 a6 [2] c2 a7 [2] d9 a1 [2] c5 a6 [2] d9 89 }

  condition:
    any of them
}