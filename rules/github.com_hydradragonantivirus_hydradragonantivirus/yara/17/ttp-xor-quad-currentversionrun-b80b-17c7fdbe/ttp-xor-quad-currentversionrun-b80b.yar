rule TTP_XOR_QUAD_CurrentVersionRun_b80b {
  strings:
    $key_b80b = { eb 64 [2] cf 6a [2] e4 46 [2] ca 64 [2] de 7f [2] d1 65 [2] cf 78 [2] cd 79 [2] d6 7f [2] ca 78 [2] d6 57 }

  condition:
    any of them
}