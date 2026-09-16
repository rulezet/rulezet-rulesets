rule TTP_XOR_QUAD_CurrentVersionRun_b725 {
  strings:
    $key_b725 = { e4 4a [2] c0 44 [2] eb 68 [2] c5 4a [2] d1 51 [2] de 4b [2] c0 56 [2] c2 57 [2] d9 51 [2] c5 56 [2] d9 79 }

  condition:
    any of them
}