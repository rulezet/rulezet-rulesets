rule TTP_XOR_QUAD_CurrentVersionRun_b476 {
  strings:
    $key_b476 = { e7 19 [2] c3 17 [2] e8 3b [2] c6 19 [2] d2 02 [2] dd 18 [2] c3 05 [2] c1 04 [2] da 02 [2] c6 05 [2] da 2a }

  condition:
    any of them
}