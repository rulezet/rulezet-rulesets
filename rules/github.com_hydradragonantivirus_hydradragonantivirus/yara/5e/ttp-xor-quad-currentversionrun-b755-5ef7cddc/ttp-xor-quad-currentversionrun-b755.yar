rule TTP_XOR_QUAD_CurrentVersionRun_b755 {
  strings:
    $key_b755 = { e4 3a [2] c0 34 [2] eb 18 [2] c5 3a [2] d1 21 [2] de 3b [2] c0 26 [2] c2 27 [2] d9 21 [2] c5 26 [2] d9 09 }

  condition:
    any of them
}