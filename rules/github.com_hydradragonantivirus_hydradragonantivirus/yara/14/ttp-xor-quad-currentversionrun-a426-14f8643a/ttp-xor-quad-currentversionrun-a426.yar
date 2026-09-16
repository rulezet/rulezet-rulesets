rule TTP_XOR_QUAD_CurrentVersionRun_a426 {
  strings:
    $key_a426 = { f7 49 [2] d3 47 [2] f8 6b [2] d6 49 [2] c2 52 [2] cd 48 [2] d3 55 [2] d1 54 [2] ca 52 [2] d6 55 [2] ca 7a }

  condition:
    any of them
}