rule TTP_XOR_QUAD_CurrentVersionRun_a4ea {
  strings:
    $key_a4ea = { f7 85 [2] d3 8b [2] f8 a7 [2] d6 85 [2] c2 9e [2] cd 84 [2] d3 99 [2] d1 98 [2] ca 9e [2] d6 99 [2] ca b6 }

  condition:
    any of them
}