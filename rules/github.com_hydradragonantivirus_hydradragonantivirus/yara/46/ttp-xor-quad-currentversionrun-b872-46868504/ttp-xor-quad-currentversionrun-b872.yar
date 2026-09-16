rule TTP_XOR_QUAD_CurrentVersionRun_b872 {
  strings:
    $key_b872 = { eb 1d [2] cf 13 [2] e4 3f [2] ca 1d [2] de 06 [2] d1 1c [2] cf 01 [2] cd 00 [2] d6 06 [2] ca 01 [2] d6 2e }

  condition:
    any of them
}