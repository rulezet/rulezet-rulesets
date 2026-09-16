rule TTP_XOR_QUAD_CurrentVersionRun_b897 {
  strings:
    $key_b897 = { eb f8 [2] cf f6 [2] e4 da [2] ca f8 [2] de e3 [2] d1 f9 [2] cf e4 [2] cd e5 [2] d6 e3 [2] ca e4 [2] d6 cb }

  condition:
    any of them
}