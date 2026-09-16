rule TTP_XOR_QUAD_CurrentVersionRun_a4f5 {
  strings:
    $key_a4f5 = { f7 9a [2] d3 94 [2] f8 b8 [2] d6 9a [2] c2 81 [2] cd 9b [2] d3 86 [2] d1 87 [2] ca 81 [2] d6 86 [2] ca a9 }

  condition:
    any of them
}