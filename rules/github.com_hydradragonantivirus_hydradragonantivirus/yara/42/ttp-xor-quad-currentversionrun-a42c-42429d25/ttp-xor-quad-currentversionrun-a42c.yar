rule TTP_XOR_QUAD_CurrentVersionRun_a42c {
  strings:
    $key_a42c = { f7 43 [2] d3 4d [2] f8 61 [2] d6 43 [2] c2 58 [2] cd 42 [2] d3 5f [2] d1 5e [2] ca 58 [2] d6 5f [2] ca 70 }

  condition:
    any of them
}