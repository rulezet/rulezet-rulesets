rule TTP_XOR_QUAD_CurrentVersionRun_b868 {
  strings:
    $key_b868 = { eb 07 [2] cf 09 [2] e4 25 [2] ca 07 [2] de 1c [2] d1 06 [2] cf 1b [2] cd 1a [2] d6 1c [2] ca 1b [2] d6 34 }

  condition:
    any of them
}