rule TTP_XOR_QUAD_CurrentVersionRun_b481 {
  strings:
    $key_b481 = { e7 ee [2] c3 e0 [2] e8 cc [2] c6 ee [2] d2 f5 [2] dd ef [2] c3 f2 [2] c1 f3 [2] da f5 [2] c6 f2 [2] da dd }

  condition:
    any of them
}