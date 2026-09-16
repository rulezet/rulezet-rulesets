rule TTP_XOR_QUAD_CurrentVersionRun_a45c {
  strings:
    $key_a45c = { f7 33 [2] d3 3d [2] f8 11 [2] d6 33 [2] c2 28 [2] cd 32 [2] d3 2f [2] d1 2e [2] ca 28 [2] d6 2f [2] ca 00 }

  condition:
    any of them
}