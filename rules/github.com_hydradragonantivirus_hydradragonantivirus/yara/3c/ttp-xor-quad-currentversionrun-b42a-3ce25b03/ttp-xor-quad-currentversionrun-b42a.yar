rule TTP_XOR_QUAD_CurrentVersionRun_b42a {
  strings:
    $key_b42a = { e7 45 [2] c3 4b [2] e8 67 [2] c6 45 [2] d2 5e [2] dd 44 [2] c3 59 [2] c1 58 [2] da 5e [2] c6 59 [2] da 76 }

  condition:
    any of them
}