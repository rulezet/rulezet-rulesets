rule TTP_XOR_QUAD_CurrentVersionRun_a413 {
  strings:
    $key_a413 = { f7 7c [2] d3 72 [2] f8 5e [2] d6 7c [2] c2 67 [2] cd 7d [2] d3 60 [2] d1 61 [2] ca 67 [2] d6 60 [2] ca 4f }

  condition:
    any of them
}