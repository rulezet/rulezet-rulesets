rule TTP_XOR_QUAD_CurrentVersionRun_a429 {
  strings:
    $key_a429 = { f7 46 [2] d3 48 [2] f8 64 [2] d6 46 [2] c2 5d [2] cd 47 [2] d3 5a [2] d1 5b [2] ca 5d [2] d6 5a [2] ca 75 }

  condition:
    any of them
}