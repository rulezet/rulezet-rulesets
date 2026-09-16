rule TTP_XOR_QUAD_CurrentVersionRun_a4f4 {
  strings:
    $key_a4f4 = { f7 9b [2] d3 95 [2] f8 b9 [2] d6 9b [2] c2 80 [2] cd 9a [2] d3 87 [2] d1 86 [2] ca 80 [2] d6 87 [2] ca a8 }

  condition:
    any of them
}