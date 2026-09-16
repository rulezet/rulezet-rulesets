rule TTP_XOR_QUAD_CurrentVersionRun_b89c {
  strings:
    $key_b89c = { eb f3 [2] cf fd [2] e4 d1 [2] ca f3 [2] de e8 [2] d1 f2 [2] cf ef [2] cd ee [2] d6 e8 [2] ca ef [2] d6 c0 }

  condition:
    any of them
}