rule TTP_XOR_QUAD_CurrentVersionRun_a3f1 {
  strings:
    $key_a3f1 = { f0 9e [2] d4 90 [2] ff bc [2] d1 9e [2] c5 85 [2] ca 9f [2] d4 82 [2] d6 83 [2] cd 85 [2] d1 82 [2] cd ad }

  condition:
    any of them
}