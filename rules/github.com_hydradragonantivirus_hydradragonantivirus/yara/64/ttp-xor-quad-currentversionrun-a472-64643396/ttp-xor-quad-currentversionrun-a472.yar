rule TTP_XOR_QUAD_CurrentVersionRun_a472 {
  strings:
    $key_a472 = { f7 1d [2] d3 13 [2] f8 3f [2] d6 1d [2] c2 06 [2] cd 1c [2] d3 01 [2] d1 00 [2] ca 06 [2] d6 01 [2] ca 2e }

  condition:
    any of them
}