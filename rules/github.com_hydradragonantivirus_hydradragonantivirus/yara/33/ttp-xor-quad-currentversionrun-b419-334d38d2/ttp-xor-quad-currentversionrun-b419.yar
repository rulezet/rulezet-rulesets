rule TTP_XOR_QUAD_CurrentVersionRun_b419 {
  strings:
    $key_b419 = { e7 76 [2] c3 78 [2] e8 54 [2] c6 76 [2] d2 6d [2] dd 77 [2] c3 6a [2] c1 6b [2] da 6d [2] c6 6a [2] da 45 }

  condition:
    any of them
}