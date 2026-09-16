rule TTP_XOR_QUAD_CurrentVersionRun_b455 {
  strings:
    $key_b455 = { e7 3a [2] c3 34 [2] e8 18 [2] c6 3a [2] d2 21 [2] dd 3b [2] c3 26 [2] c1 27 [2] da 21 [2] c6 26 [2] da 09 }

  condition:
    any of them
}