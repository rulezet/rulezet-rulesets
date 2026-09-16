rule TTP_XOR_QUAD_CurrentVersionRun_b851 {
  strings:
    $key_b851 = { eb 3e [2] cf 30 [2] e4 1c [2] ca 3e [2] de 25 [2] d1 3f [2] cf 22 [2] cd 23 [2] d6 25 [2] ca 22 [2] d6 0d }

  condition:
    any of them
}