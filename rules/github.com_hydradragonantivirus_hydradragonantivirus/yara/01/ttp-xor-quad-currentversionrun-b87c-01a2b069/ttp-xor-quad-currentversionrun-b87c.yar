rule TTP_XOR_QUAD_CurrentVersionRun_b87c {
  strings:
    $key_b87c = { eb 13 [2] cf 1d [2] e4 31 [2] ca 13 [2] de 08 [2] d1 12 [2] cf 0f [2] cd 0e [2] d6 08 [2] ca 0f [2] d6 20 }

  condition:
    any of them
}