rule TTP_XOR_QUAD_CurrentVersionRun_a4ed {
  strings:
    $key_a4ed = { f7 82 [2] d3 8c [2] f8 a0 [2] d6 82 [2] c2 99 [2] cd 83 [2] d3 9e [2] d1 9f [2] ca 99 [2] d6 9e [2] ca b1 }

  condition:
    any of them
}