rule TTP_XOR_QUAD_CurrentVersionRun_b82c {
  strings:
    $key_b82c = { eb 43 [2] cf 4d [2] e4 61 [2] ca 43 [2] de 58 [2] d1 42 [2] cf 5f [2] cd 5e [2] d6 58 [2] ca 5f [2] d6 70 }

  condition:
    any of them
}