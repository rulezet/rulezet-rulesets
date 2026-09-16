rule TTP_XOR_QUAD_CurrentVersionRun_a451 {
  strings:
    $key_a451 = { f7 3e [2] d3 30 [2] f8 1c [2] d6 3e [2] c2 25 [2] cd 3f [2] d3 22 [2] d1 23 [2] ca 25 [2] d6 22 [2] ca 0d }

  condition:
    any of them
}