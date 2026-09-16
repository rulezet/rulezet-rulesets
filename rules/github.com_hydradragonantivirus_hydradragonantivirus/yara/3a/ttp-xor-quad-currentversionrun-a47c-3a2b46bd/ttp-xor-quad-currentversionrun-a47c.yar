rule TTP_XOR_QUAD_CurrentVersionRun_a47c {
  strings:
    $key_a47c = { f7 13 [2] d3 1d [2] f8 31 [2] d6 13 [2] c2 08 [2] cd 12 [2] d3 0f [2] d1 0e [2] ca 08 [2] d6 0f [2] ca 20 }

  condition:
    any of them
}