rule TTP_XOR_QUAD_CurrentVersionRun_b86b {
  strings:
    $key_b86b = { eb 04 [2] cf 0a [2] e4 26 [2] ca 04 [2] de 1f [2] d1 05 [2] cf 18 [2] cd 19 [2] d6 1f [2] ca 18 [2] d6 37 }

  condition:
    any of them
}