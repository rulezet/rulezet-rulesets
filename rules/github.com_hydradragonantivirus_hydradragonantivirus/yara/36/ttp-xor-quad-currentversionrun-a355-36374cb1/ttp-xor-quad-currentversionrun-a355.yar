rule TTP_XOR_QUAD_CurrentVersionRun_a355 {
  strings:
    $key_a355 = { f0 3a [2] d4 34 [2] ff 18 [2] d1 3a [2] c5 21 [2] ca 3b [2] d4 26 [2] d6 27 [2] cd 21 [2] d1 26 [2] cd 09 }

  condition:
    any of them
}