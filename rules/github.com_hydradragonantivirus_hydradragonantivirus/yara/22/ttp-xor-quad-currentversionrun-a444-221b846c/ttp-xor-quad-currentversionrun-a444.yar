rule TTP_XOR_QUAD_CurrentVersionRun_a444 {
  strings:
    $key_a444 = { f7 2b [2] d3 25 [2] f8 09 [2] d6 2b [2] c2 30 [2] cd 2a [2] d3 37 [2] d1 36 [2] ca 30 [2] d6 37 [2] ca 18 }

  condition:
    any of them
}