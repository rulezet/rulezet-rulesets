rule TTP_XOR_QUAD_CurrentVersionRun_b8ea {
  strings:
    $key_b8ea = { eb 85 [2] cf 8b [2] e4 a7 [2] ca 85 [2] de 9e [2] d1 84 [2] cf 99 [2] cd 98 [2] d6 9e [2] ca 99 [2] d6 b6 }

  condition:
    any of them
}