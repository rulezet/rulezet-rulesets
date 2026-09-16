rule TTP_XOR_QUAD_CurrentVersionRun_a457 {
  strings:
    $key_a457 = { f7 38 [2] d3 36 [2] f8 1a [2] d6 38 [2] c2 23 [2] cd 39 [2] d3 24 [2] d1 25 [2] ca 23 [2] d6 24 [2] ca 0b }

  condition:
    any of them
}