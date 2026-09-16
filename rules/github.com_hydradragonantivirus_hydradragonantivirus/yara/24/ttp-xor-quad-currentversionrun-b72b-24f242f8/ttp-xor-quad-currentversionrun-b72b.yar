rule TTP_XOR_QUAD_CurrentVersionRun_b72b {
  strings:
    $key_b72b = { e4 44 [2] c0 4a [2] eb 66 [2] c5 44 [2] d1 5f [2] de 45 [2] c0 58 [2] c2 59 [2] d9 5f [2] c5 58 [2] d9 77 }

  condition:
    any of them
}