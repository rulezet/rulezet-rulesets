rule TTP_XOR_QUAD_CurrentVersionRun_b4fa {
  strings:
    $key_b4fa = { e7 95 [2] c3 9b [2] e8 b7 [2] c6 95 [2] d2 8e [2] dd 94 [2] c3 89 [2] c1 88 [2] da 8e [2] c6 89 [2] da a6 }

  condition:
    any of them
}