rule TTP_XOR_QUAD_CurrentVersionRun_ab19 {
  strings:
    $key_ab19 = { f8 76 [2] dc 78 [2] f7 54 [2] d9 76 [2] cd 6d [2] c2 77 [2] dc 6a [2] de 6b [2] c5 6d [2] d9 6a [2] c5 45 }

  condition:
    any of them
}