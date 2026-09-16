rule TTP_XOR_QUAD_CurrentVersionRun_a44c {
  strings:
    $key_a44c = { f7 23 [2] d3 2d [2] f8 01 [2] d6 23 [2] c2 38 [2] cd 22 [2] d3 3f [2] d1 3e [2] ca 38 [2] d6 3f [2] ca 10 }

  condition:
    any of them
}