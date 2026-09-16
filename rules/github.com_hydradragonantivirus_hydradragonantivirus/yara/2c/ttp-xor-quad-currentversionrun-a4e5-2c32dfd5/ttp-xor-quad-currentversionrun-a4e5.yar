rule TTP_XOR_QUAD_CurrentVersionRun_a4e5 {
  strings:
    $key_a4e5 = { f7 8a [2] d3 84 [2] f8 a8 [2] d6 8a [2] c2 91 [2] cd 8b [2] d3 96 [2] d1 97 [2] ca 91 [2] d6 96 [2] ca b9 }

  condition:
    any of them
}