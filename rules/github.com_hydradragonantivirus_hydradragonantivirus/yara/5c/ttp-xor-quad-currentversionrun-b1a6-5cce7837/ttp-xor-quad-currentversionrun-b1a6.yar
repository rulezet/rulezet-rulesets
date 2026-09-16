rule TTP_XOR_QUAD_CurrentVersionRun_b1a6 {
  strings:
    $key_b1a6 = { e2 c9 [2] c6 c7 [2] ed eb [2] c3 c9 [2] d7 d2 [2] d8 c8 [2] c6 d5 [2] c4 d4 [2] df d2 [2] c3 d5 [2] df fa }

  condition:
    any of them
}