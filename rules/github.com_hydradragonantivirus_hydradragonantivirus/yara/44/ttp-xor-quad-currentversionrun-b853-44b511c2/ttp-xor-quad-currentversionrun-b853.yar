rule TTP_XOR_QUAD_CurrentVersionRun_b853 {
  strings:
    $key_b853 = { eb 3c [2] cf 32 [2] e4 1e [2] ca 3c [2] de 27 [2] d1 3d [2] cf 20 [2] cd 21 [2] d6 27 [2] ca 20 [2] d6 0f }

  condition:
    any of them
}