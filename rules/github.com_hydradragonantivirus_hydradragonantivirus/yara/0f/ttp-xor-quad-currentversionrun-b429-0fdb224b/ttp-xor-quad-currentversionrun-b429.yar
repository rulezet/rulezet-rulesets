rule TTP_XOR_QUAD_CurrentVersionRun_b429 {
  strings:
    $key_b429 = { e7 46 [2] c3 48 [2] e8 64 [2] c6 46 [2] d2 5d [2] dd 47 [2] c3 5a [2] c1 5b [2] da 5d [2] c6 5a [2] da 75 }

  condition:
    any of them
}