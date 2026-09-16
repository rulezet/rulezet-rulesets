rule TTP_XOR_QUAD_CurrentVersionRun_ab25 {
  strings:
    $key_ab25 = { f8 4a [2] dc 44 [2] f7 68 [2] d9 4a [2] cd 51 [2] c2 4b [2] dc 56 [2] de 57 [2] c5 51 [2] d9 56 [2] c5 79 }

  condition:
    any of them
}