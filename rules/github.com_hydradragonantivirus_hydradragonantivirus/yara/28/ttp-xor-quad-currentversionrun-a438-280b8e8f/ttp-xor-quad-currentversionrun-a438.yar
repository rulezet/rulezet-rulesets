rule TTP_XOR_QUAD_CurrentVersionRun_a438 {
  strings:
    $key_a438 = { f7 57 [2] d3 59 [2] f8 75 [2] d6 57 [2] c2 4c [2] cd 56 [2] d3 4b [2] d1 4a [2] ca 4c [2] d6 4b [2] ca 64 }

  condition:
    any of them
}