rule TTP_XOR_QUAD_CurrentVersionRun_a417 {
  strings:
    $key_a417 = { f7 78 [2] d3 76 [2] f8 5a [2] d6 78 [2] c2 63 [2] cd 79 [2] d3 64 [2] d1 65 [2] ca 63 [2] d6 64 [2] ca 4b }

  condition:
    any of them
}