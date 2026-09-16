rule TTP_XOR_QUAD_CurrentVersionRun_b4eb {
  strings:
    $key_b4eb = { e7 84 [2] c3 8a [2] e8 a6 [2] c6 84 [2] d2 9f [2] dd 85 [2] c3 98 [2] c1 99 [2] da 9f [2] c6 98 [2] da b7 }

  condition:
    any of them
}