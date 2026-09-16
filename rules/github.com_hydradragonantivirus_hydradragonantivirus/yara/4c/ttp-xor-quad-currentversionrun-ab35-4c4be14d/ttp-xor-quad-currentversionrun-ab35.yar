rule TTP_XOR_QUAD_CurrentVersionRun_ab35 {
  strings:
    $key_ab35 = { f8 5a [2] dc 54 [2] f7 78 [2] d9 5a [2] cd 41 [2] c2 5b [2] dc 46 [2] de 47 [2] c5 41 [2] d9 46 [2] c5 69 }

  condition:
    any of them
}