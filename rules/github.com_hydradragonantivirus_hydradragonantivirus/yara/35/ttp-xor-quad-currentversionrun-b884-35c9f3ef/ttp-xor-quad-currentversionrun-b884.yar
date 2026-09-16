rule TTP_XOR_QUAD_CurrentVersionRun_b884 {
  strings:
    $key_b884 = { eb eb [2] cf e5 [2] e4 c9 [2] ca eb [2] de f0 [2] d1 ea [2] cf f7 [2] cd f6 [2] d6 f0 [2] ca f7 [2] d6 d8 }

  condition:
    any of them
}