rule TTP_XOR_QUAD_CurrentVersionRun_a40a {
  strings:
    $key_a40a = { f7 65 [2] d3 6b [2] f8 47 [2] d6 65 [2] c2 7e [2] cd 64 [2] d3 79 [2] d1 78 [2] ca 7e [2] d6 79 [2] ca 56 }

  condition:
    any of them
}