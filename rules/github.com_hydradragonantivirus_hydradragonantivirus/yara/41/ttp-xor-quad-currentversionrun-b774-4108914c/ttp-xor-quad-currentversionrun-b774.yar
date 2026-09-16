rule TTP_XOR_QUAD_CurrentVersionRun_b774 {
  strings:
    $key_b774 = { e4 1b [2] c0 15 [2] eb 39 [2] c5 1b [2] d1 00 [2] de 1a [2] c0 07 [2] c2 06 [2] d9 00 [2] c5 07 [2] d9 28 }

  condition:
    any of them
}