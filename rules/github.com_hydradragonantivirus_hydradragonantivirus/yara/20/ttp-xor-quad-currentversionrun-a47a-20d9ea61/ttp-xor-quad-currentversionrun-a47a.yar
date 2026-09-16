rule TTP_XOR_QUAD_CurrentVersionRun_a47a {
  strings:
    $key_a47a = { f7 15 [2] d3 1b [2] f8 37 [2] d6 15 [2] c2 0e [2] cd 14 [2] d3 09 [2] d1 08 [2] ca 0e [2] d6 09 [2] ca 26 }

  condition:
    any of them
}