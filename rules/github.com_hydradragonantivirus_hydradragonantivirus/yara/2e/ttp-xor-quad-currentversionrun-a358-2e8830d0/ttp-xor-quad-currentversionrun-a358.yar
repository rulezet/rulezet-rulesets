rule TTP_XOR_QUAD_CurrentVersionRun_a358 {
  strings:
    $key_a358 = { f0 37 [2] d4 39 [2] ff 15 [2] d1 37 [2] c5 2c [2] ca 36 [2] d4 2b [2] d6 2a [2] cd 2c [2] d1 2b [2] cd 04 }

  condition:
    any of them
}