rule TTP_XOR_QUAD_CurrentVersionRun_b8fd {
  strings:
    $key_b8fd = { eb 92 [2] cf 9c [2] e4 b0 [2] ca 92 [2] de 89 [2] d1 93 [2] cf 8e [2] cd 8f [2] d6 89 [2] ca 8e [2] d6 a1 }

  condition:
    any of them
}