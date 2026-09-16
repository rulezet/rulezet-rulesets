rule TTP_XOR_QUAD_CurrentVersionRun_b4e4 {
  strings:
    $key_b4e4 = { e7 8b [2] c3 85 [2] e8 a9 [2] c6 8b [2] d2 90 [2] dd 8a [2] c3 97 [2] c1 96 [2] da 90 [2] c6 97 [2] da b8 }

  condition:
    any of them
}