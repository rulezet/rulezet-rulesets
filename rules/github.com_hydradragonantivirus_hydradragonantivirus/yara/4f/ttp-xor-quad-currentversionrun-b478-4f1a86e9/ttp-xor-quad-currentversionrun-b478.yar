rule TTP_XOR_QUAD_CurrentVersionRun_b478 {
  strings:
    $key_b478 = { e7 17 [2] c3 19 [2] e8 35 [2] c6 17 [2] d2 0c [2] dd 16 [2] c3 0b [2] c1 0a [2] da 0c [2] c6 0b [2] da 24 }

  condition:
    any of them
}