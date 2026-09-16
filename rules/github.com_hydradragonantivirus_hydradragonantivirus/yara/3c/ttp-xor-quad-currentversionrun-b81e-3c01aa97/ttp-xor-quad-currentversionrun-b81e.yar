rule TTP_XOR_QUAD_CurrentVersionRun_b81e {
  strings:
    $key_b81e = { eb 71 [2] cf 7f [2] e4 53 [2] ca 71 [2] de 6a [2] d1 70 [2] cf 6d [2] cd 6c [2] d6 6a [2] ca 6d [2] d6 42 }

  condition:
    any of them
}