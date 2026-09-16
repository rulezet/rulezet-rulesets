rule TTP_XOR_QUAD_CurrentVersionRun_b414 {
  strings:
    $key_b414 = { e7 7b [2] c3 75 [2] e8 59 [2] c6 7b [2] d2 60 [2] dd 7a [2] c3 67 [2] c1 66 [2] da 60 [2] c6 67 [2] da 48 }

  condition:
    any of them
}