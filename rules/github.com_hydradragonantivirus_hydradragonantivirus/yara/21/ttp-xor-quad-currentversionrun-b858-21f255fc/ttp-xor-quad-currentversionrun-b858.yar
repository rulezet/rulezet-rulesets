rule TTP_XOR_QUAD_CurrentVersionRun_b858 {
  strings:
    $key_b858 = { eb 37 [2] cf 39 [2] e4 15 [2] ca 37 [2] de 2c [2] d1 36 [2] cf 2b [2] cd 2a [2] d6 2c [2] ca 2b [2] d6 04 }

  condition:
    any of them
}