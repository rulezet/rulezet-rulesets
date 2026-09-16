rule TTP_XOR_QUAD_CurrentVersionRun_a369 {
  strings:
    $key_a369 = { f0 06 [2] d4 08 [2] ff 24 [2] d1 06 [2] c5 1d [2] ca 07 [2] d4 1a [2] d6 1b [2] cd 1d [2] d1 1a [2] cd 35 }

  condition:
    any of them
}