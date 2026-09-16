rule TTP_XOR_QUAD_CurrentVersionRun_a46b {
  strings:
    $key_a46b = { f7 04 [2] d3 0a [2] f8 26 [2] d6 04 [2] c2 1f [2] cd 05 [2] d3 18 [2] d1 19 [2] ca 1f [2] d6 18 [2] ca 37 }

  condition:
    any of them
}