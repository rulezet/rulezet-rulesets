rule TTP_XOR_QUAD_CurrentVersionRun_b746 {
  strings:
    $key_b746 = { e4 29 [2] c0 27 [2] eb 0b [2] c5 29 [2] d1 32 [2] de 28 [2] c0 35 [2] c2 34 [2] d9 32 [2] c5 35 [2] d9 1a }

  condition:
    any of them
}