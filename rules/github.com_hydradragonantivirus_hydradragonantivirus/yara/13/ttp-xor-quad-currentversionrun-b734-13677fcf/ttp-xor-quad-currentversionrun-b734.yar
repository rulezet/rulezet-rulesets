rule TTP_XOR_QUAD_CurrentVersionRun_b734 {
  strings:
    $key_b734 = { e4 5b [2] c0 55 [2] eb 79 [2] c5 5b [2] d1 40 [2] de 5a [2] c0 47 [2] c2 46 [2] d9 40 [2] c5 47 [2] d9 68 }

  condition:
    any of them
}