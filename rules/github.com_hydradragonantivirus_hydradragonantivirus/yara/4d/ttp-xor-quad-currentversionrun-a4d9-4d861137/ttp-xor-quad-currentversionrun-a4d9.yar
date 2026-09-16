rule TTP_XOR_QUAD_CurrentVersionRun_a4d9 {
  strings:
    $key_a4d9 = { f7 b6 [2] d3 b8 [2] f8 94 [2] d6 b6 [2] c2 ad [2] cd b7 [2] d3 aa [2] d1 ab [2] ca ad [2] d6 aa [2] ca 85 }

  condition:
    any of them
}