rule TTP_XOR_QUAD_CurrentVersionRun_b4f8 {
  strings:
    $key_b4f8 = { e7 97 [2] c3 99 [2] e8 b5 [2] c6 97 [2] d2 8c [2] dd 96 [2] c3 8b [2] c1 8a [2] da 8c [2] c6 8b [2] da a4 }

  condition:
    any of them
}