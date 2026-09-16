rule TTP_XOR_QUAD_CurrentVersionRun_b4e8 {
  strings:
    $key_b4e8 = { e7 87 [2] c3 89 [2] e8 a5 [2] c6 87 [2] d2 9c [2] dd 86 [2] c3 9b [2] c1 9a [2] da 9c [2] c6 9b [2] da b4 }

  condition:
    any of them
}