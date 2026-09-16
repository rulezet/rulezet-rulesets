rule TTP_XOR_QUAD_CurrentVersionRun_a347 {
  strings:
    $key_a347 = { f0 28 [2] d4 26 [2] ff 0a [2] d1 28 [2] c5 33 [2] ca 29 [2] d4 34 [2] d6 35 [2] cd 33 [2] d1 34 [2] cd 1b }

  condition:
    any of them
}