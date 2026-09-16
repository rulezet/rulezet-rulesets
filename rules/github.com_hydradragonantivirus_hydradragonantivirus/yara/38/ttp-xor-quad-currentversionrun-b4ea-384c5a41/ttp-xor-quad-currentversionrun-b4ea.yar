rule TTP_XOR_QUAD_CurrentVersionRun_b4ea {
  strings:
    $key_b4ea = { e7 85 [2] c3 8b [2] e8 a7 [2] c6 85 [2] d2 9e [2] dd 84 [2] c3 99 [2] c1 98 [2] da 9e [2] c6 99 [2] da b6 }

  condition:
    any of them
}