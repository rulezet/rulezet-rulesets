rule TTP_XOR_QUAD_CurrentVersionRun_b8ff {
  strings:
    $key_b8ff = { eb 90 [2] cf 9e [2] e4 b2 [2] ca 90 [2] de 8b [2] d1 91 [2] cf 8c [2] cd 8d [2] d6 8b [2] ca 8c [2] d6 a3 }

  condition:
    any of them
}