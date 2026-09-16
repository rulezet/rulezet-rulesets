rule TTP_XOR_QUAD_CurrentVersionRun_a4f8 {
  strings:
    $key_a4f8 = { f7 97 [2] d3 99 [2] f8 b5 [2] d6 97 [2] c2 8c [2] cd 96 [2] d3 8b [2] d1 8a [2] ca 8c [2] d6 8b [2] ca a4 }

  condition:
    any of them
}