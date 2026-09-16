rule TTP_XOR_QUAD_CurrentVersionRun_a42a {
  strings:
    $key_a42a = { f7 45 [2] d3 4b [2] f8 67 [2] d6 45 [2] c2 5e [2] cd 44 [2] d3 59 [2] d1 58 [2] ca 5e [2] d6 59 [2] ca 76 }

  condition:
    any of them
}