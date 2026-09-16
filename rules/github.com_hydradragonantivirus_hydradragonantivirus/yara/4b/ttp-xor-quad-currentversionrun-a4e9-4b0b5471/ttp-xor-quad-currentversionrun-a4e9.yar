rule TTP_XOR_QUAD_CurrentVersionRun_a4e9 {
  strings:
    $key_a4e9 = { f7 86 [2] d3 88 [2] f8 a4 [2] d6 86 [2] c2 9d [2] cd 87 [2] d3 9a [2] d1 9b [2] ca 9d [2] d6 9a [2] ca b5 }

  condition:
    any of them
}