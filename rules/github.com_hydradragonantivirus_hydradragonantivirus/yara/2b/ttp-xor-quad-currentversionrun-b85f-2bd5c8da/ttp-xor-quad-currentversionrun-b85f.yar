rule TTP_XOR_QUAD_CurrentVersionRun_b85f {
  strings:
    $key_b85f = { eb 30 [2] cf 3e [2] e4 12 [2] ca 30 [2] de 2b [2] d1 31 [2] cf 2c [2] cd 2d [2] d6 2b [2] ca 2c [2] d6 03 }

  condition:
    any of them
}