rule TTP_XOR_QUAD_CurrentVersionRun_b1fb {
  strings:
    $key_b1fb = { e2 94 [2] c6 9a [2] ed b6 [2] c3 94 [2] d7 8f [2] d8 95 [2] c6 88 [2] c4 89 [2] df 8f [2] c3 88 [2] df a7 }

  condition:
    any of them
}