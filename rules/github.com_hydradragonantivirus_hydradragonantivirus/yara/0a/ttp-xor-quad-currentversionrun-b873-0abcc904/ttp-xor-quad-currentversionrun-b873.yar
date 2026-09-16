rule TTP_XOR_QUAD_CurrentVersionRun_b873 {
  strings:
    $key_b873 = { eb 1c [2] cf 12 [2] e4 3e [2] ca 1c [2] de 07 [2] d1 1d [2] cf 00 [2] cd 01 [2] d6 07 [2] ca 00 [2] d6 2f }

  condition:
    any of them
}