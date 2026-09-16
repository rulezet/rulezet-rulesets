rule TTP_XOR_QUAD_CurrentVersionRun_ab79 {
  strings:
    $key_ab79 = { f8 16 [2] dc 18 [2] f7 34 [2] d9 16 [2] cd 0d [2] c2 17 [2] dc 0a [2] de 0b [2] c5 0d [2] d9 0a [2] c5 25 }

  condition:
    any of them
}