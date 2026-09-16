rule TTP_XOR_QUAD_CurrentVersionRun_a377 {
  strings:
    $key_a377 = { f0 18 [2] d4 16 [2] ff 3a [2] d1 18 [2] c5 03 [2] ca 19 [2] d4 04 [2] d6 05 [2] cd 03 [2] d1 04 [2] cd 2b }

  condition:
    any of them
}