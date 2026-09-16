rule TTP_XOR_QUAD_CurrentVersionRun_a401 {
  strings:
    $key_a401 = { f7 6e [2] d3 60 [2] f8 4c [2] d6 6e [2] c2 75 [2] cd 6f [2] d3 72 [2] d1 73 [2] ca 75 [2] d6 72 [2] ca 5d }

  condition:
    any of them
}