rule TTP_XOR_QUAD_CurrentVersionRun_a381 {
  strings:
    $key_a381 = { f0 ee [2] d4 e0 [2] ff cc [2] d1 ee [2] c5 f5 [2] ca ef [2] d4 f2 [2] d6 f3 [2] cd f5 [2] d1 f2 [2] cd dd }

  condition:
    any of them
}