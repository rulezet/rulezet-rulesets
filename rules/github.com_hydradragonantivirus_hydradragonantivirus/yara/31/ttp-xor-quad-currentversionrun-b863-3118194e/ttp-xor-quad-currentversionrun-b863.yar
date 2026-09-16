rule TTP_XOR_QUAD_CurrentVersionRun_b863 {
  strings:
    $key_b863 = { eb 0c [2] cf 02 [2] e4 2e [2] ca 0c [2] de 17 [2] d1 0d [2] cf 10 [2] cd 11 [2] d6 17 [2] ca 10 [2] d6 3f }

  condition:
    any of them
}