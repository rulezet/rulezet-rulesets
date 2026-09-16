rule TTP_XOR_QUAD_CurrentVersionRun_b817 {
  strings:
    $key_b817 = { eb 78 [2] cf 76 [2] e4 5a [2] ca 78 [2] de 63 [2] d1 79 [2] cf 64 [2] cd 65 [2] d6 63 [2] ca 64 [2] d6 4b }

  condition:
    any of them
}