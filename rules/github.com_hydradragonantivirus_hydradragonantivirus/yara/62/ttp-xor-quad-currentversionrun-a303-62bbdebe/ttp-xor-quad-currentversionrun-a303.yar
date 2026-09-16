rule TTP_XOR_QUAD_CurrentVersionRun_a303 {
  strings:
    $key_a303 = { f0 6c [2] d4 62 [2] ff 4e [2] d1 6c [2] c5 77 [2] ca 6d [2] d4 70 [2] d6 71 [2] cd 77 [2] d1 70 [2] cd 5f }

  condition:
    any of them
}