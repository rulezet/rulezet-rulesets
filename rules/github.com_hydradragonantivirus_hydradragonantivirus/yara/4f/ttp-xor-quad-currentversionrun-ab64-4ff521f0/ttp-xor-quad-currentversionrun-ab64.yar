rule TTP_XOR_QUAD_CurrentVersionRun_ab64 {
  strings:
    $key_ab64 = { f8 0b [2] dc 05 [2] f7 29 [2] d9 0b [2] cd 10 [2] c2 0a [2] dc 17 [2] de 16 [2] c5 10 [2] d9 17 [2] c5 38 }

  condition:
    any of them
}