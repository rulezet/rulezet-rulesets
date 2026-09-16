rule TTP_XOR_QUAD_CurrentVersionRun_b808 {
  strings:
    $key_b808 = { eb 67 [2] cf 69 [2] e4 45 [2] ca 67 [2] de 7c [2] d1 66 [2] cf 7b [2] cd 7a [2] d6 7c [2] ca 7b [2] d6 54 }

  condition:
    any of them
}