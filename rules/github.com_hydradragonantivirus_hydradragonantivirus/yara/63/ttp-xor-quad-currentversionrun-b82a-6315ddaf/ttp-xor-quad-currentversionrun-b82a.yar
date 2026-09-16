rule TTP_XOR_QUAD_CurrentVersionRun_b82a {
  strings:
    $key_b82a = { eb 45 [2] cf 4b [2] e4 67 [2] ca 45 [2] de 5e [2] d1 44 [2] cf 59 [2] cd 58 [2] d6 5e [2] ca 59 [2] d6 76 }

  condition:
    any of them
}