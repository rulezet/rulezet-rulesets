rule TTP_XOR_QUAD_CurrentVersionRun_a4e7 {
  strings:
    $key_a4e7 = { f7 88 [2] d3 86 [2] f8 aa [2] d6 88 [2] c2 93 [2] cd 89 [2] d3 94 [2] d1 95 [2] ca 93 [2] d6 94 [2] ca bb }

  condition:
    any of them
}