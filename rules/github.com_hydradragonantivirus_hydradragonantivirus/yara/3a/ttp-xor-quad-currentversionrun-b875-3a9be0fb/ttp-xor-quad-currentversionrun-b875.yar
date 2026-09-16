rule TTP_XOR_QUAD_CurrentVersionRun_b875 {
  strings:
    $key_b875 = { eb 1a [2] cf 14 [2] e4 38 [2] ca 1a [2] de 01 [2] d1 1b [2] cf 06 [2] cd 07 [2] d6 01 [2] ca 06 [2] d6 29 }

  condition:
    any of them
}