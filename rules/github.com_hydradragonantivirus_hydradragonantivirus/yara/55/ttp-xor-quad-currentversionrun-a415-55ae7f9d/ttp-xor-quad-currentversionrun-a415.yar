rule TTP_XOR_QUAD_CurrentVersionRun_a415 {
  strings:
    $key_a415 = { f7 7a [2] d3 74 [2] f8 58 [2] d6 7a [2] c2 61 [2] cd 7b [2] d3 66 [2] d1 67 [2] ca 61 [2] d6 66 [2] ca 49 }

  condition:
    any of them
}