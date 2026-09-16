rule TTP_XOR_QUAD_CurrentVersionRun_a455 {
  strings:
    $key_a455 = { f7 3a [2] d3 34 [2] f8 18 [2] d6 3a [2] c2 21 [2] cd 3b [2] d3 26 [2] d1 27 [2] ca 21 [2] d6 26 [2] ca 09 }

  condition:
    any of them
}