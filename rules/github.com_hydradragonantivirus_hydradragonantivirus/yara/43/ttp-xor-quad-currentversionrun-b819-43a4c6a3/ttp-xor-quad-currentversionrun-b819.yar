rule TTP_XOR_QUAD_CurrentVersionRun_b819 {
  strings:
    $key_b819 = { eb 76 [2] cf 78 [2] e4 54 [2] ca 76 [2] de 6d [2] d1 77 [2] cf 6a [2] cd 6b [2] d6 6d [2] ca 6a [2] d6 45 }

  condition:
    any of them
}