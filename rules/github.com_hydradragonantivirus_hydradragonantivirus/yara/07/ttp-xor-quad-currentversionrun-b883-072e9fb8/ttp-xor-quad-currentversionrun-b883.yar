rule TTP_XOR_QUAD_CurrentVersionRun_b883 {
  strings:
    $key_b883 = { eb ec [2] cf e2 [2] e4 ce [2] ca ec [2] de f7 [2] d1 ed [2] cf f0 [2] cd f1 [2] d6 f7 [2] ca f0 [2] d6 df }

  condition:
    any of them
}