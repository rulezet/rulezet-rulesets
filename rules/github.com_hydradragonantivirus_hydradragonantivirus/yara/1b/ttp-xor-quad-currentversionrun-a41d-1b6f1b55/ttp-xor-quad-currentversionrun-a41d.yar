rule TTP_XOR_QUAD_CurrentVersionRun_a41d {
  strings:
    $key_a41d = { f7 72 [2] d3 7c [2] f8 50 [2] d6 72 [2] c2 69 [2] cd 73 [2] d3 6e [2] d1 6f [2] ca 69 [2] d6 6e [2] ca 41 }

  condition:
    any of them
}