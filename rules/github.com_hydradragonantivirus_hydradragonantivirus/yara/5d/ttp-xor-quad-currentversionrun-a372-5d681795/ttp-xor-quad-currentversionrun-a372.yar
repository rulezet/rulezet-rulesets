rule TTP_XOR_QUAD_CurrentVersionRun_a372 {
  strings:
    $key_a372 = { f0 1d [2] d4 13 [2] ff 3f [2] d1 1d [2] c5 06 [2] ca 1c [2] d4 01 [2] d6 00 [2] cd 06 [2] d1 01 [2] cd 2e }

  condition:
    any of them
}