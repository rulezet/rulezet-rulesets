rule TTP_XOR_QUAD_CurrentVersionRun_a4e4 {
  strings:
    $key_a4e4 = { f7 8b [2] d3 85 [2] f8 a9 [2] d6 8b [2] c2 90 [2] cd 8a [2] d3 97 [2] d1 96 [2] ca 90 [2] d6 97 [2] ca b8 }

  condition:
    any of them
}