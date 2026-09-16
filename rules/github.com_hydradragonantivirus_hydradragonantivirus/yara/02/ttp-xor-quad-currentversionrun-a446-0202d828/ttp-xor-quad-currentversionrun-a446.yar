rule TTP_XOR_QUAD_CurrentVersionRun_a446 {
  strings:
    $key_a446 = { f7 29 [2] d3 27 [2] f8 0b [2] d6 29 [2] c2 32 [2] cd 28 [2] d3 35 [2] d1 34 [2] ca 32 [2] d6 35 [2] ca 1a }

  condition:
    any of them
}