rule TTP_XOR_QUAD_CurrentVersionRun_b454 {
  strings:
    $key_b454 = { e7 3b [2] c3 35 [2] e8 19 [2] c6 3b [2] d2 20 [2] dd 3a [2] c3 27 [2] c1 26 [2] da 20 [2] c6 27 [2] da 08 }

  condition:
    any of them
}