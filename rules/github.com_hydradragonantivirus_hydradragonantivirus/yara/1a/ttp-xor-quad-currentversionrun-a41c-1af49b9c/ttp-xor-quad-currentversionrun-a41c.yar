rule TTP_XOR_QUAD_CurrentVersionRun_a41c {
  strings:
    $key_a41c = { f7 73 [2] d3 7d [2] f8 51 [2] d6 73 [2] c2 68 [2] cd 72 [2] d3 6f [2] d1 6e [2] ca 68 [2] d6 6f [2] ca 40 }

  condition:
    any of them
}