rule TTP_XOR_QUAD_CurrentVersionRun_a427 {
  strings:
    $key_a427 = { f7 48 [2] d3 46 [2] f8 6a [2] d6 48 [2] c2 53 [2] cd 49 [2] d3 54 [2] d1 55 [2] ca 53 [2] d6 54 [2] ca 7b }

  condition:
    any of them
}