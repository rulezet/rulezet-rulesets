rule TTP_XOR_QUAD_CurrentVersionRun_b4ee {
  strings:
    $key_b4ee = { e7 81 [2] c3 8f [2] e8 a3 [2] c6 81 [2] d2 9a [2] dd 80 [2] c3 9d [2] c1 9c [2] da 9a [2] c6 9d [2] da b2 }

  condition:
    any of them
}