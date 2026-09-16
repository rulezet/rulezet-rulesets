rule TTP_XOR_QUAD_CurrentVersionRun_b4ef {
  strings:
    $key_b4ef = { e7 80 [2] c3 8e [2] e8 a2 [2] c6 80 [2] d2 9b [2] dd 81 [2] c3 9c [2] c1 9d [2] da 9b [2] c6 9c [2] da b3 }

  condition:
    any of them
}