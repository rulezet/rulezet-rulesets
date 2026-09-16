rule TTP_XOR_QUAD_CurrentVersionRun_b4f3 {
  strings:
    $key_b4f3 = { e7 9c [2] c3 92 [2] e8 be [2] c6 9c [2] d2 87 [2] dd 9d [2] c3 80 [2] c1 81 [2] da 87 [2] c6 80 [2] da af }

  condition:
    any of them
}