rule TTP_XOR_QUAD_CurrentVersionRun_b754 {
  strings:
    $key_b754 = { e4 3b [2] c0 35 [2] eb 19 [2] c5 3b [2] d1 20 [2] de 3a [2] c0 27 [2] c2 26 [2] d9 20 [2] c5 27 [2] d9 08 }

  condition:
    any of them
}