rule TTP_XOR_QUAD_CurrentVersionRun_a428 {
  strings:
    $key_a428 = { f7 47 [2] d3 49 [2] f8 65 [2] d6 47 [2] c2 5c [2] cd 46 [2] d3 5b [2] d1 5a [2] ca 5c [2] d6 5b [2] ca 74 }

  condition:
    any of them
}