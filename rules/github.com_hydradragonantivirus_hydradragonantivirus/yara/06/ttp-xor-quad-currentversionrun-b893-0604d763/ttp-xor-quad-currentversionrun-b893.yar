rule TTP_XOR_QUAD_CurrentVersionRun_b893 {
  strings:
    $key_b893 = { eb fc [2] cf f2 [2] e4 de [2] ca fc [2] de e7 [2] d1 fd [2] cf e0 [2] cd e1 [2] d6 e7 [2] ca e0 [2] d6 cf }

  condition:
    any of them
}