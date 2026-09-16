rule TTP_XOR_QUAD_CurrentVersionRun_b834 {
  strings:
    $key_b834 = { eb 5b [2] cf 55 [2] e4 79 [2] ca 5b [2] de 40 [2] d1 5a [2] cf 47 [2] cd 46 [2] d6 40 [2] ca 47 [2] d6 68 }

  condition:
    any of them
}