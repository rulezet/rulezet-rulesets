rule TTP_XOR_QUAD_CurrentVersionRun_b4a6 {
  strings:
    $key_b4a6 = { e7 c9 [2] c3 c7 [2] e8 eb [2] c6 c9 [2] d2 d2 [2] dd c8 [2] c3 d5 [2] c1 d4 [2] da d2 [2] c6 d5 [2] da fa }

  condition:
    any of them
}