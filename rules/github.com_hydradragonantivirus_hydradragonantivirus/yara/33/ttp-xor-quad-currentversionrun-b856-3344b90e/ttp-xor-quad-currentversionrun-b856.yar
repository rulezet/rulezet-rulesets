rule TTP_XOR_QUAD_CurrentVersionRun_b856 {
  strings:
    $key_b856 = { eb 39 [2] cf 37 [2] e4 1b [2] ca 39 [2] de 22 [2] d1 38 [2] cf 25 [2] cd 24 [2] d6 22 [2] ca 25 [2] d6 0a }

  condition:
    any of them
}