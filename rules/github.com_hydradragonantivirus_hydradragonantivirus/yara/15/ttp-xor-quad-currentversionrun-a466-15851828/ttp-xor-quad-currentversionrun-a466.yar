rule TTP_XOR_QUAD_CurrentVersionRun_a466 {
  strings:
    $key_a466 = { f7 09 [2] d3 07 [2] f8 2b [2] d6 09 [2] c2 12 [2] cd 08 [2] d3 15 [2] d1 14 [2] ca 12 [2] d6 15 [2] ca 3a }

  condition:
    any of them
}