rule TTP_XOR_QUAD_CurrentVersionRun_a443 {
  strings:
    $key_a443 = { f7 2c [2] d3 22 [2] f8 0e [2] d6 2c [2] c2 37 [2] cd 2d [2] d3 30 [2] d1 31 [2] ca 37 [2] d6 30 [2] ca 1f }

  condition:
    any of them
}