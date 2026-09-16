rule TTP_XOR_QUAD_CurrentVersionRun_b406 {
  strings:
    $key_b406 = { e7 69 [2] c3 67 [2] e8 4b [2] c6 69 [2] d2 72 [2] dd 68 [2] c3 75 [2] c1 74 [2] da 72 [2] c6 75 [2] da 5a }

  condition:
    any of them
}