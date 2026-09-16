rule TTP_XOR_QUAD_CurrentVersionRun_b896 {
  strings:
    $key_b896 = { eb f9 [2] cf f7 [2] e4 db [2] ca f9 [2] de e2 [2] d1 f8 [2] cf e5 [2] cd e4 [2] d6 e2 [2] ca e5 [2] d6 ca }

  condition:
    any of them
}