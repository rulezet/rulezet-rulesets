rule TTP_XOR_QUAD_CurrentVersionRun_b881 {
  strings:
    $key_b881 = { eb ee [2] cf e0 [2] e4 cc [2] ca ee [2] de f5 [2] d1 ef [2] cf f2 [2] cd f3 [2] d6 f5 [2] ca f2 [2] d6 dd }

  condition:
    any of them
}