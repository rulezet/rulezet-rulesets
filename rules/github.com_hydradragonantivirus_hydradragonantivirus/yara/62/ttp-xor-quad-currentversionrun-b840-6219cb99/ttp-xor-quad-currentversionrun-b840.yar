rule TTP_XOR_QUAD_CurrentVersionRun_b840 {
  strings:
    $key_b840 = { eb 2f [2] cf 21 [2] e4 0d [2] ca 2f [2] de 34 [2] d1 2e [2] cf 33 [2] cd 32 [2] d6 34 [2] ca 33 [2] d6 1c }

  condition:
    any of them
}