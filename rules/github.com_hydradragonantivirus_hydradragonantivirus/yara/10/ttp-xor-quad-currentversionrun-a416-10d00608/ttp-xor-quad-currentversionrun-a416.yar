rule TTP_XOR_QUAD_CurrentVersionRun_a416 {
  strings:
    $key_a416 = { f7 79 [2] d3 77 [2] f8 5b [2] d6 79 [2] c2 62 [2] cd 78 [2] d3 65 [2] d1 64 [2] ca 62 [2] d6 65 [2] ca 4a }

  condition:
    any of them
}