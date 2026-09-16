rule TTP_XOR_QUAD_CurrentVersionRun_b87a {
  strings:
    $key_b87a = { eb 15 [2] cf 1b [2] e4 37 [2] ca 15 [2] de 0e [2] d1 14 [2] cf 09 [2] cd 08 [2] d6 0e [2] ca 09 [2] d6 26 }

  condition:
    any of them
}