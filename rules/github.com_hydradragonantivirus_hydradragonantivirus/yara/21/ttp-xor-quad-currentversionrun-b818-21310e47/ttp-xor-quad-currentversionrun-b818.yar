rule TTP_XOR_QUAD_CurrentVersionRun_b818 {
  strings:
    $key_b818 = { eb 77 [2] cf 79 [2] e4 55 [2] ca 77 [2] de 6c [2] d1 76 [2] cf 6b [2] cd 6a [2] d6 6c [2] ca 6b [2] d6 44 }

  condition:
    any of them
}