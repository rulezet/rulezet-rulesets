rule TTP_XOR_QUAD_CurrentVersionRun_b1e7 {
  strings:
    $key_b1e7 = { e2 88 [2] c6 86 [2] ed aa [2] c3 88 [2] d7 93 [2] d8 89 [2] c6 94 [2] c4 95 [2] df 93 [2] c3 94 [2] df bb }

  condition:
    any of them
}