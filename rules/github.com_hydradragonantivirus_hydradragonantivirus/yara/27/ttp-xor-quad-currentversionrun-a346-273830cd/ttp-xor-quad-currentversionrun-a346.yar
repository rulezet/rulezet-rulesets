rule TTP_XOR_QUAD_CurrentVersionRun_a346 {
  strings:
    $key_a346 = { f0 29 [2] d4 27 [2] ff 0b [2] d1 29 [2] c5 32 [2] ca 28 [2] d4 35 [2] d6 34 [2] cd 32 [2] d1 35 [2] cd 1a }

  condition:
    any of them
}