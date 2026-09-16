rule TTP_XOR_QUAD_CurrentVersionRun_b84d {
  strings:
    $key_b84d = { eb 22 [2] cf 2c [2] e4 00 [2] ca 22 [2] de 39 [2] d1 23 [2] cf 3e [2] cd 3f [2] d6 39 [2] ca 3e [2] d6 11 }

  condition:
    any of them
}