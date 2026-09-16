rule TTP_XOR_QUAD_CurrentVersionRun_b86c {
  strings:
    $key_b86c = { eb 03 [2] cf 0d [2] e4 21 [2] ca 03 [2] de 18 [2] d1 02 [2] cf 1f [2] cd 1e [2] d6 18 [2] ca 1f [2] d6 30 }

  condition:
    any of them
}