rule TTP_XOR_QUAD_CurrentVersionRun_a437 {
  strings:
    $key_a437 = { f7 58 [2] d3 56 [2] f8 7a [2] d6 58 [2] c2 43 [2] cd 59 [2] d3 44 [2] d1 45 [2] ca 43 [2] d6 44 [2] ca 6b }

  condition:
    any of them
}