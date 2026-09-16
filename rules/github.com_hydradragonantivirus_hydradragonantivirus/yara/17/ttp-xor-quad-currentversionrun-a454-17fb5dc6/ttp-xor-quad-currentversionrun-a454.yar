rule TTP_XOR_QUAD_CurrentVersionRun_a454 {
  strings:
    $key_a454 = { f7 3b [2] d3 35 [2] f8 19 [2] d6 3b [2] c2 20 [2] cd 3a [2] d3 27 [2] d1 26 [2] ca 20 [2] d6 27 [2] ca 08 }

  condition:
    any of them
}