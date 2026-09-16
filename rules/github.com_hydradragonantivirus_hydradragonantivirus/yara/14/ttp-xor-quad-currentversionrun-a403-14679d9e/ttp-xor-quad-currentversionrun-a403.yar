rule TTP_XOR_QUAD_CurrentVersionRun_a403 {
  strings:
    $key_a403 = { f7 6c [2] d3 62 [2] f8 4e [2] d6 6c [2] c2 77 [2] cd 6d [2] d3 70 [2] d1 71 [2] ca 77 [2] d6 70 [2] ca 5f }

  condition:
    any of them
}