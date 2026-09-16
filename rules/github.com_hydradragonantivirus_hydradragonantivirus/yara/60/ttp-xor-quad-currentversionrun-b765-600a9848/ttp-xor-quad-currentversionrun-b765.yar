rule TTP_XOR_QUAD_CurrentVersionRun_b765 {
  strings:
    $key_b765 = { e4 0a [2] c0 04 [2] eb 28 [2] c5 0a [2] d1 11 [2] de 0b [2] c0 16 [2] c2 17 [2] d9 11 [2] c5 16 [2] d9 39 }

  condition:
    any of them
}