rule TTP_XOR_QUAD_CurrentVersionRun_b468 {
  strings:
    $key_b468 = { e7 07 [2] c3 09 [2] e8 25 [2] c6 07 [2] d2 1c [2] dd 06 [2] c3 1b [2] c1 1a [2] da 1c [2] c6 1b [2] da 34 }

  condition:
    any of them
}