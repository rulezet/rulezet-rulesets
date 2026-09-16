rule TTP_XOR_QUAD_CurrentVersionRun_a348 {
  strings:
    $key_a348 = { f0 27 [2] d4 29 [2] ff 05 [2] d1 27 [2] c5 3c [2] ca 26 [2] d4 3b [2] d6 3a [2] cd 3c [2] d1 3b [2] cd 14 }

  condition:
    any of them
}