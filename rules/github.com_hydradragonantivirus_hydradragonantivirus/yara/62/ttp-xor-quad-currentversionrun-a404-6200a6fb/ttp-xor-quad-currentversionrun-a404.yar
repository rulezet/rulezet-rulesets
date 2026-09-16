rule TTP_XOR_QUAD_CurrentVersionRun_a404 {
  strings:
    $key_a404 = { f7 6b [2] d3 65 [2] f8 49 [2] d6 6b [2] c2 70 [2] cd 6a [2] d3 77 [2] d1 76 [2] ca 70 [2] d6 77 [2] ca 58 }

  condition:
    any of them
}