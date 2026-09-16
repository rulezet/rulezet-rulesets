rule TTP_XOR_QUAD_CurrentVersionRun_b804 {
  strings:
    $key_b804 = { eb 6b [2] cf 65 [2] e4 49 [2] ca 6b [2] de 70 [2] d1 6a [2] cf 77 [2] cd 76 [2] d6 70 [2] ca 77 [2] d6 58 }

  condition:
    any of them
}