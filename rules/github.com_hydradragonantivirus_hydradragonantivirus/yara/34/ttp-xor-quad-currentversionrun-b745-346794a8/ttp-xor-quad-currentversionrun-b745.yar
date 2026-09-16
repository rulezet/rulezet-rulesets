rule TTP_XOR_QUAD_CurrentVersionRun_b745 {
  strings:
    $key_b745 = { e4 2a [2] c0 24 [2] eb 08 [2] c5 2a [2] d1 31 [2] de 2b [2] c0 36 [2] c2 37 [2] d9 31 [2] c5 36 [2] d9 19 }

  condition:
    any of them
}