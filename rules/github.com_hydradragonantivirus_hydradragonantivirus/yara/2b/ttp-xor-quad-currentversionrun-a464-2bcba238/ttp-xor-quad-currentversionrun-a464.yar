rule TTP_XOR_QUAD_CurrentVersionRun_a464 {
  strings:
    $key_a464 = { f7 0b [2] d3 05 [2] f8 29 [2] d6 0b [2] c2 10 [2] cd 0a [2] d3 17 [2] d1 16 [2] ca 10 [2] d6 17 [2] ca 38 }

  condition:
    any of them
}