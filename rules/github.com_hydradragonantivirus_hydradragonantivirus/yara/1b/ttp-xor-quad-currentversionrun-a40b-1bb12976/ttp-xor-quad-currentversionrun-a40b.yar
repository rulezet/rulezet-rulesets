rule TTP_XOR_QUAD_CurrentVersionRun_a40b {
  strings:
    $key_a40b = { f7 64 [2] d3 6a [2] f8 46 [2] d6 64 [2] c2 7f [2] cd 65 [2] d3 78 [2] d1 79 [2] ca 7f [2] d6 78 [2] ca 57 }

  condition:
    any of them
}