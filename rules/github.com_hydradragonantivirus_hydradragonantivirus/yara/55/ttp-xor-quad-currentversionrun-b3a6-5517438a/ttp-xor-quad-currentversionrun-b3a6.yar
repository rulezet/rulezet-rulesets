rule TTP_XOR_QUAD_CurrentVersionRun_b3a6 {
  strings:
    $key_b3a6 = { e0 c9 [2] c4 c7 [2] ef eb [2] c1 c9 [2] d5 d2 [2] da c8 [2] c4 d5 [2] c6 d4 [2] dd d2 [2] c1 d5 [2] dd fa }

  condition:
    any of them
}