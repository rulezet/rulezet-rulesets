rule TTP_XOR_QUAD_CurrentVersionRun_a474 {
  strings:
    $key_a474 = { f7 1b [2] d3 15 [2] f8 39 [2] d6 1b [2] c2 00 [2] cd 1a [2] d3 07 [2] d1 06 [2] ca 00 [2] d6 07 [2] ca 28 }

  condition:
    any of them
}