rule TTP_XOR_QUAD_CurrentVersionRun_b829 {
  strings:
    $key_b829 = { eb 46 [2] cf 48 [2] e4 64 [2] ca 46 [2] de 5d [2] d1 47 [2] cf 5a [2] cd 5b [2] d6 5d [2] ca 5a [2] d6 75 }

  condition:
    any of them
}