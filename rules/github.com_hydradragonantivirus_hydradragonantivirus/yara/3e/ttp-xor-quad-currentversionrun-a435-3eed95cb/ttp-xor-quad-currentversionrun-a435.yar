rule TTP_XOR_QUAD_CurrentVersionRun_a435 {
  strings:
    $key_a435 = { f7 5a [2] d3 54 [2] f8 78 [2] d6 5a [2] c2 41 [2] cd 5b [2] d3 46 [2] d1 47 [2] ca 41 [2] d6 46 [2] ca 69 }

  condition:
    any of them
}