rule TTP_XOR_QUAD_CurrentVersionRun_a4d7 {
  strings:
    $key_a4d7 = { f7 b8 [2] d3 b6 [2] f8 9a [2] d6 b8 [2] c2 a3 [2] cd b9 [2] d3 a4 [2] d1 a5 [2] ca a3 [2] d6 a4 [2] ca 8b }

  condition:
    any of them
}