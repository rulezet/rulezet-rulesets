rule TTP_XOR_QUAD_CurrentVersionRun_b479 {
  strings:
    $key_b479 = { e7 16 [2] c3 18 [2] e8 34 [2] c6 16 [2] d2 0d [2] dd 17 [2] c3 0a [2] c1 0b [2] da 0d [2] c6 0a [2] da 25 }

  condition:
    any of them
}