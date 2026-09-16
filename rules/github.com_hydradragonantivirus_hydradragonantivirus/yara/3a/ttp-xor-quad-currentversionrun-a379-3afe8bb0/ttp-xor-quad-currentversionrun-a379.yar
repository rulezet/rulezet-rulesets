rule TTP_XOR_QUAD_CurrentVersionRun_a379 {
  strings:
    $key_a379 = { f0 16 [2] d4 18 [2] ff 34 [2] d1 16 [2] c5 0d [2] ca 17 [2] d4 0a [2] d6 0b [2] cd 0d [2] d1 0a [2] cd 25 }

  condition:
    any of them
}