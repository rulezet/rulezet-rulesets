rule TTP_XOR_QUAD_CurrentVersionRun_a304 {
  strings:
    $key_a304 = { f0 6b [2] d4 65 [2] ff 49 [2] d1 6b [2] c5 70 [2] ca 6a [2] d4 77 [2] d6 76 [2] cd 70 [2] d1 77 [2] cd 58 }

  condition:
    any of them
}