rule TTP_XOR_QUAD_CurrentVersionRun_b86e {
  strings:
    $key_b86e = { eb 01 [2] cf 0f [2] e4 23 [2] ca 01 [2] de 1a [2] d1 00 [2] cf 1d [2] cd 1c [2] d6 1a [2] ca 1d [2] d6 32 }

  condition:
    any of them
}