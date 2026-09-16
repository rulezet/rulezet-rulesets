rule TTP_XOR_QUAD_CurrentVersionRun_a45d {
  strings:
    $key_a45d = { f7 32 [2] d3 3c [2] f8 10 [2] d6 32 [2] c2 29 [2] cd 33 [2] d3 2e [2] d1 2f [2] ca 29 [2] d6 2e [2] ca 01 }

  condition:
    any of them
}