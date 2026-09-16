rule TTP_XOR_QUAD_CurrentVersionRun_b84e {
  strings:
    $key_b84e = { eb 21 [2] cf 2f [2] e4 03 [2] ca 21 [2] de 3a [2] d1 20 [2] cf 3d [2] cd 3c [2] d6 3a [2] ca 3d [2] d6 12 }

  condition:
    any of them
}