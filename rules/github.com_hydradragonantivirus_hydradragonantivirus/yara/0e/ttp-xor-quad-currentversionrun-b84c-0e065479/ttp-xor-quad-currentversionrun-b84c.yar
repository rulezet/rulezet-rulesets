rule TTP_XOR_QUAD_CurrentVersionRun_b84c {
  strings:
    $key_b84c = { eb 23 [2] cf 2d [2] e4 01 [2] ca 23 [2] de 38 [2] d1 22 [2] cf 3f [2] cd 3e [2] d6 38 [2] ca 3f [2] d6 10 }

  condition:
    any of them
}