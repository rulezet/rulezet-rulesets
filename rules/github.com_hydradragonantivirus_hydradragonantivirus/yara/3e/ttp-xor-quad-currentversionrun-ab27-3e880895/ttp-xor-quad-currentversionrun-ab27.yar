rule TTP_XOR_QUAD_CurrentVersionRun_ab27 {
  strings:
    $key_ab27 = { f8 48 [2] dc 46 [2] f7 6a [2] d9 48 [2] cd 53 [2] c2 49 [2] dc 54 [2] de 55 [2] c5 53 [2] d9 54 [2] c5 7b }

  condition:
    any of them
}