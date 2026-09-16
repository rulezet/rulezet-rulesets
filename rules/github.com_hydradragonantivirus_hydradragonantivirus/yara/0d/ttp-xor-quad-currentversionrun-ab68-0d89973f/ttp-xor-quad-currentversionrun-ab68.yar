rule TTP_XOR_QUAD_CurrentVersionRun_ab68 {
  strings:
    $key_ab68 = { f8 07 [2] dc 09 [2] f7 25 [2] d9 07 [2] cd 1c [2] c2 06 [2] dc 1b [2] de 1a [2] c5 1c [2] d9 1b [2] c5 34 }

  condition:
    any of them
}