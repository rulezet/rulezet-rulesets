rule TTP_XOR_QUAD_CurrentVersionRun_ab74 {
  strings:
    $key_ab74 = { f8 1b [2] dc 15 [2] f7 39 [2] d9 1b [2] cd 00 [2] c2 1a [2] dc 07 [2] de 06 [2] c5 00 [2] d9 07 [2] c5 28 }

  condition:
    any of them
}