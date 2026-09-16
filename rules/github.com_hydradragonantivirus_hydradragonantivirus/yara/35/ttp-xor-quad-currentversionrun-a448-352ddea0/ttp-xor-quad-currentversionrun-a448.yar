rule TTP_XOR_QUAD_CurrentVersionRun_a448 {
  strings:
    $key_a448 = { f7 27 [2] d3 29 [2] f8 05 [2] d6 27 [2] c2 3c [2] cd 26 [2] d3 3b [2] d1 3a [2] ca 3c [2] d6 3b [2] ca 14 }

  condition:
    any of them
}