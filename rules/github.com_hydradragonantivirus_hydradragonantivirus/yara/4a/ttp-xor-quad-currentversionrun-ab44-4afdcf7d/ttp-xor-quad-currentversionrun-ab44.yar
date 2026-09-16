rule TTP_XOR_QUAD_CurrentVersionRun_ab44 {
  strings:
    $key_ab44 = { f8 2b [2] dc 25 [2] f7 09 [2] d9 2b [2] cd 30 [2] c2 2a [2] dc 37 [2] de 36 [2] c5 30 [2] d9 37 [2] c5 18 }

  condition:
    any of them
}