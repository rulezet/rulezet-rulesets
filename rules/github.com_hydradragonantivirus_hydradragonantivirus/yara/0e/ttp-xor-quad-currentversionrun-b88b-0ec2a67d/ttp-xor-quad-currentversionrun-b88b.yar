rule TTP_XOR_QUAD_CurrentVersionRun_b88b {
  strings:
    $key_b88b = { eb e4 [2] cf ea [2] e4 c6 [2] ca e4 [2] de ff [2] d1 e5 [2] cf f8 [2] cd f9 [2] d6 ff [2] ca f8 [2] d6 d7 }

  condition:
    any of them
}