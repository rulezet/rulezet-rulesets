rule TTP_XOR_QUAD_CurrentVersionRun_b87e {
  strings:
    $key_b87e = { eb 11 [2] cf 1f [2] e4 33 [2] ca 11 [2] de 0a [2] d1 10 [2] cf 0d [2] cd 0c [2] d6 0a [2] ca 0d [2] d6 22 }

  condition:
    any of them
}