rule TTP_XOR_QUAD_CurrentVersionRun_b1fa {
  strings:
    $key_b1fa = { e2 95 [2] c6 9b [2] ed b7 [2] c3 95 [2] d7 8e [2] d8 94 [2] c6 89 [2] c4 88 [2] df 8e [2] c3 89 [2] df a6 }

  condition:
    any of them
}