rule TTP_XOR_QUAD_CurrentVersionRun_a411 {
  strings:
    $key_a411 = { f7 7e [2] d3 70 [2] f8 5c [2] d6 7e [2] c2 65 [2] cd 7f [2] d3 62 [2] d1 63 [2] ca 65 [2] d6 62 [2] ca 4d }

  condition:
    any of them
}