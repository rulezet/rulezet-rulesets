rule TTP_XOR_QUAD_CurrentVersionRun_b803 {
  strings:
    $key_b803 = { eb 6c [2] cf 62 [2] e4 4e [2] ca 6c [2] de 77 [2] d1 6d [2] cf 70 [2] cd 71 [2] d6 77 [2] ca 70 [2] d6 5f }

  condition:
    any of them
}