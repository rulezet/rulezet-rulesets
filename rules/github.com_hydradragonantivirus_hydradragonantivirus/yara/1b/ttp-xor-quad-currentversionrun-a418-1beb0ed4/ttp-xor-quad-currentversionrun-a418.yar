rule TTP_XOR_QUAD_CurrentVersionRun_a418 {
  strings:
    $key_a418 = { f7 77 [2] d3 79 [2] f8 55 [2] d6 77 [2] c2 6c [2] cd 76 [2] d3 6b [2] d1 6a [2] ca 6c [2] d6 6b [2] ca 44 }

  condition:
    any of them
}