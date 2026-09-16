rule TTP_XOR_QUAD_CurrentVersionRun_b763 {
  strings:
    $key_b763 = { e4 0c [2] c0 02 [2] eb 2e [2] c5 0c [2] d1 17 [2] de 0d [2] c0 10 [2] c2 11 [2] d9 17 [2] c5 10 [2] d9 3f }

  condition:
    any of them
}