rule TTP_XOR_QUAD_CurrentVersionRun_a44d {
  strings:
    $key_a44d = { f7 22 [2] d3 2c [2] f8 00 [2] d6 22 [2] c2 39 [2] cd 23 [2] d3 3e [2] d1 3f [2] ca 39 [2] d6 3e [2] ca 11 }

  condition:
    any of them
}