rule TTP_XOR_QUAD_CurrentVersionRun_a410 {
  strings:
    $key_a410 = { f7 7f [2] d3 71 [2] f8 5d [2] d6 7f [2] c2 64 [2] cd 7e [2] d3 63 [2] d1 62 [2] ca 64 [2] d6 63 [2] ca 4c }

  condition:
    any of them
}