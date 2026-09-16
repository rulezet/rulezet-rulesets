rule TTP_XOR_QUAD_CurrentVersionRun_a4fc {
  strings:
    $key_a4fc = { f7 93 [2] d3 9d [2] f8 b1 [2] d6 93 [2] c2 88 [2] cd 92 [2] d3 8f [2] d1 8e [2] ca 88 [2] d6 8f [2] ca a0 }

  condition:
    any of them
}