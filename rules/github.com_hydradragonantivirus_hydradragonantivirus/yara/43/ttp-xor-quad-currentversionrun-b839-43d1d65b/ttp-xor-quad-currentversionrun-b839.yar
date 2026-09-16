rule TTP_XOR_QUAD_CurrentVersionRun_b839 {
  strings:
    $key_b839 = { eb 56 [2] cf 58 [2] e4 74 [2] ca 56 [2] de 4d [2] d1 57 [2] cf 4a [2] cd 4b [2] d6 4d [2] ca 4a [2] d6 65 }

  condition:
    any of them
}