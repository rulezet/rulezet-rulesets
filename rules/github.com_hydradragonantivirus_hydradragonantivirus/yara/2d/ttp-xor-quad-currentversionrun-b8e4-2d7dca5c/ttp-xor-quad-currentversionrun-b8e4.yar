rule TTP_XOR_QUAD_CurrentVersionRun_b8e4 {
  strings:
    $key_b8e4 = { eb 8b [2] cf 85 [2] e4 a9 [2] ca 8b [2] de 90 [2] d1 8a [2] cf 97 [2] cd 96 [2] d6 90 [2] ca 97 [2] d6 b8 }

  condition:
    any of them
}