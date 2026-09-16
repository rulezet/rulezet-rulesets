rule TTP_XOR_QUAD_CurrentVersionRun_b845 {
  strings:
    $key_b845 = { eb 2a [2] cf 24 [2] e4 08 [2] ca 2a [2] de 31 [2] d1 2b [2] cf 36 [2] cd 37 [2] d6 31 [2] ca 36 [2] d6 19 }

  condition:
    any of them
}