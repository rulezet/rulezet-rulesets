rule TTP_XOR_QUAD_CurrentVersionRun_b823 {
  strings:
    $key_b823 = { eb 4c [2] cf 42 [2] e4 6e [2] ca 4c [2] de 57 [2] d1 4d [2] cf 50 [2] cd 51 [2] d6 57 [2] ca 50 [2] d6 7f }

  condition:
    any of them
}