rule TTP_XOR_QUAD_CurrentVersionRun_b83b {
  strings:
    $key_b83b = { eb 54 [2] cf 5a [2] e4 76 [2] ca 54 [2] de 4f [2] d1 55 [2] cf 48 [2] cd 49 [2] d6 4f [2] ca 48 [2] d6 67 }

  condition:
    any of them
}