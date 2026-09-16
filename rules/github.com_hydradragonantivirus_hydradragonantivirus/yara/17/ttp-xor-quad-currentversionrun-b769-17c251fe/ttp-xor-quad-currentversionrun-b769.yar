rule TTP_XOR_QUAD_CurrentVersionRun_b769 {
  strings:
    $key_b769 = { e4 06 [2] c0 08 [2] eb 24 [2] c5 06 [2] d1 1d [2] de 07 [2] c0 1a [2] c2 1b [2] d9 1d [2] c5 1a [2] d9 35 }

  condition:
    any of them
}