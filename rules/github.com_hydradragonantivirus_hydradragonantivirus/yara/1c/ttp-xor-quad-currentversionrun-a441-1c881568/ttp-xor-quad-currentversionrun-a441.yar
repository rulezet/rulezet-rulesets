rule TTP_XOR_QUAD_CurrentVersionRun_a441 {
  strings:
    $key_a441 = { f7 2e [2] d3 20 [2] f8 0c [2] d6 2e [2] c2 35 [2] cd 2f [2] d3 32 [2] d1 33 [2] ca 35 [2] d6 32 [2] ca 1d }

  condition:
    any of them
}