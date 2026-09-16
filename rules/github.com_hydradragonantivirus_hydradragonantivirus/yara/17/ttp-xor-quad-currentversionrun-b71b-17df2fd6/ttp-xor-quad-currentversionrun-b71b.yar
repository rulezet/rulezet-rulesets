rule TTP_XOR_QUAD_CurrentVersionRun_b71b {
  strings:
    $key_b71b = { e4 74 [2] c0 7a [2] eb 56 [2] c5 74 [2] d1 6f [2] de 75 [2] c0 68 [2] c2 69 [2] d9 6f [2] c5 68 [2] d9 47 }

  condition:
    any of them
}