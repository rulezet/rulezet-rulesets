rule TTP_XOR_QUAD_CurrentVersionRun_a400 {
  strings:
    $key_a400 = { f7 6f [2] d3 61 [2] f8 4d [2] d6 6f [2] c2 74 [2] cd 6e [2] d3 73 [2] d1 72 [2] ca 74 [2] d6 73 [2] ca 5c }

  condition:
    any of them
}