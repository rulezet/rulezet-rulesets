rule TTP_XOR_QUAD_CurrentVersionRun_b0a6 {
  strings:
    $key_b0a6 = { e3 c9 [2] c7 c7 [2] ec eb [2] c2 c9 [2] d6 d2 [2] d9 c8 [2] c7 d5 [2] c5 d4 [2] de d2 [2] c2 d5 [2] de fa }

  condition:
    any of them
}