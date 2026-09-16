rule TTP_XOR_QUAD_CurrentVersionRun_b465 {
  strings:
    $key_b465 = { e7 0a [2] c3 04 [2] e8 28 [2] c6 0a [2] d2 11 [2] dd 0b [2] c3 16 [2] c1 17 [2] da 11 [2] c6 16 [2] da 39 }

  condition:
    any of them
}