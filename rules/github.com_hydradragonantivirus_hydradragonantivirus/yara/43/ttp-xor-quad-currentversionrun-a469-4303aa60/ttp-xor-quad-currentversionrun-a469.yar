rule TTP_XOR_QUAD_CurrentVersionRun_a469 {
  strings:
    $key_a469 = { f7 06 [2] d3 08 [2] f8 24 [2] d6 06 [2] c2 1d [2] cd 07 [2] d3 1a [2] d1 1b [2] ca 1d [2] d6 1a [2] ca 35 }

  condition:
    any of them
}