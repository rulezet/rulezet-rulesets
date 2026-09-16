rule TTP_XOR_QUAD_CurrentVersionRun_b405 {
  strings:
    $key_b405 = { e7 6a [2] c3 64 [2] e8 48 [2] c6 6a [2] d2 71 [2] dd 6b [2] c3 76 [2] c1 77 [2] da 71 [2] c6 76 [2] da 59 }

  condition:
    any of them
}