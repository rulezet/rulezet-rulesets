rule TTP_XOR_QUAD_CurrentVersionRun_b42b {
  strings:
    $key_b42b = { e7 44 [2] c3 4a [2] e8 66 [2] c6 44 [2] d2 5f [2] dd 45 [2] c3 58 [2] c1 59 [2] da 5f [2] c6 58 [2] da 77 }

  condition:
    any of them
}