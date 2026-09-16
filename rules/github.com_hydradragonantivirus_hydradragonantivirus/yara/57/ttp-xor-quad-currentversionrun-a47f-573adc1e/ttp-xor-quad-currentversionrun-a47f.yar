rule TTP_XOR_QUAD_CurrentVersionRun_a47f {
  strings:
    $key_a47f = { f7 10 [2] d3 1e [2] f8 32 [2] d6 10 [2] c2 0b [2] cd 11 [2] d3 0c [2] d1 0d [2] ca 0b [2] d6 0c [2] ca 23 }

  condition:
    any of them
}