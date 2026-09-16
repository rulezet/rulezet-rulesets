rule TTP_XOR_QUAD_CurrentVersionRun_a405 {
  strings:
    $key_a405 = { f7 6a [2] d3 64 [2] f8 48 [2] d6 6a [2] c2 71 [2] cd 6b [2] d3 76 [2] d1 77 [2] ca 71 [2] d6 76 [2] ca 59 }

  condition:
    any of them
}