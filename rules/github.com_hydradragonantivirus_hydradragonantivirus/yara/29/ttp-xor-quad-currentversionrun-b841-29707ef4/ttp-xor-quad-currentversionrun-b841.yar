rule TTP_XOR_QUAD_CurrentVersionRun_b841 {
  strings:
    $key_b841 = { eb 2e [2] cf 20 [2] e4 0c [2] ca 2e [2] de 35 [2] d1 2f [2] cf 32 [2] cd 33 [2] d6 35 [2] ca 32 [2] d6 1d }

  condition:
    any of them
}