rule TTP_XOR_QUAD_CurrentVersionRun_a449 {
  strings:
    $key_a449 = { f7 26 [2] d3 28 [2] f8 04 [2] d6 26 [2] c2 3d [2] cd 27 [2] d3 3a [2] d1 3b [2] ca 3d [2] d6 3a [2] ca 15 }

  condition:
    any of them
}