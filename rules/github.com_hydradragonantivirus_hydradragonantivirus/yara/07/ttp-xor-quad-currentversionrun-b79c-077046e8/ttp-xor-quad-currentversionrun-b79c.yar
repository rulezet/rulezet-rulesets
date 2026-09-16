rule TTP_XOR_QUAD_CurrentVersionRun_b79c {
  strings:
    $key_b79c = { e4 f3 [2] c0 fd [2] eb d1 [2] c5 f3 [2] d1 e8 [2] de f2 [2] c0 ef [2] c2 ee [2] d9 e8 [2] c5 ef [2] d9 c0 }

  condition:
    any of them
}