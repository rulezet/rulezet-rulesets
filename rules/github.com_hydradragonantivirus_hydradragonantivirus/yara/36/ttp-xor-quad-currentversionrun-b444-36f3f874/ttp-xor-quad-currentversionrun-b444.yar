rule TTP_XOR_QUAD_CurrentVersionRun_b444 {
  strings:
    $key_b444 = { e7 2b [2] c3 25 [2] e8 09 [2] c6 2b [2] d2 30 [2] dd 2a [2] c3 37 [2] c1 36 [2] da 30 [2] c6 37 [2] da 18 }

  condition:
    any of them
}